#!/usr/bin/env perl
#
# Generates t/fixtures/ from spec/fixtures/core/.
#
# Valid fixtures are re-signed with real keys so the validator can do
# full Nostr crypto verification. Invalid fixtures are copied as-is
# since they fail Overnet structural checks before crypto is reached.
#
use strictures 2;
use English qw(-no_match_vars);
use File::Basename;
use File::Path qw(make_path);
use File::Spec;
use JSON ();

use Carp qw(croak);
use Net::Nostr::Event;
use Net::Nostr::Key;

our $VERSION = '0.001';

exit main();

sub main {
  my $json       = _json();
  my $script_dir = dirname(__FILE__);
  my $paths      = _fixture_paths($script_dir);
  my $keys       = _fixture_keys();
  my $events     = _generated_reference_events($json, $paths->{spec_dir}, $keys);

  _ensure_directory($paths->{spec_dir}, 'Spec fixtures');
  make_path($paths->{out_dir});

  my @files = _fixture_files($paths->{spec_dir});
  for my $file (@files) {
    _write_generated_fixture(
      file   => $file,
      json   => $json,
      keys   => $keys,
      events => $events,
      paths  => $paths,
    );
  }

  _print_generated_count(scalar @files, $paths->{out_dir});

  return 0;
}

sub _json {
  my $json = JSON->new;
  $json->utf8;
  $json->pretty;
  $json->canonical;
  return $json;
}

sub _fixture_paths {
  my ($script_dir) = @_;
  return {
    out_dir  => File::Spec->catdir($script_dir, 'fixtures'),
    spec_dir => _spec_fixture_dir($script_dir),
  };
}

sub _fixture_keys {
  return {
    native   => Net::Nostr::Key->new,
    adapter  => Net::Nostr::Key->new,
    delegate => Net::Nostr::Key->new,
  };
}

sub _generated_reference_events {
  my ($json, $spec_dir, $keys) = @_;
  return {
    native => _generate_native_event(
      json => $json,
      key  => $keys->{native},
      path => File::Spec->catfile($spec_dir, 'valid-native-event.json'),
    ),
    delegation => _generate_delegation_event(
      json         => $json,
      key          => $keys->{native},
      delegate_key => $keys->{delegate},
      path         => File::Spec->catfile($spec_dir, 'valid-delegation-event.json'),
    ),
  };
}

sub _ensure_directory {
  my ($dir, $label) = @_;
  if (!(-d $dir)) {
    croak "$label not found at $dir";
  }
  return;
}

sub _fixture_files {
  my ($spec_dir) = @_;
  opendir my $dir_handle, $spec_dir
    or croak "Can't open $spec_dir: $OS_ERROR";

  my @files = sort grep {/[.]json\z/smx} readdir $dir_handle;
  closedir $dir_handle
    or croak "Can't close $spec_dir: $OS_ERROR";

  return @files;
}

sub _write_generated_fixture {
  my (%args) = @_;
  my $fixture = _read_json_fixture($args{json}, File::Spec->catfile($args{paths}{spec_dir}, $args{file}));

  _sign_valid_fixture($fixture, $args{json}, $args{keys}, $args{events});
  _resolve_target_fixture($fixture, $args{file}, $args{events});
  _resolve_delegation_fixture($fixture, $args{file}, $args{events});
  _resolve_delegation_override($fixture, $args{json}, $args{keys}, $args{paths}{spec_dir});
  _apply_delegate_pubkey_context($fixture, $args{keys});

  _write_json_fixture(
    json    => $args{json},
    fixture => $fixture,
    path    => File::Spec->catfile($args{paths}{out_dir}, $args{file}),
  );

  return;
}

sub _sign_valid_fixture {
  my ($fixture, $json, $keys, $events) = @_;
  if (!($fixture->{expected}{overnet_valid})) {
    return;
  }

  my $input        = $fixture->{input};
  my $selected_key = _signing_key_for_fixture($fixture, $keys);
  my @tags         = _rewritten_tags_for_signing($input, $selected_key, $events);
  my $content      = _content_for_signing($input, $json, $keys);

  my $event = $selected_key->create_event(
    kind       => $input->{kind},
    content    => $content,
    tags       => \@tags,
    created_at => $input->{created_at},
  );

  $fixture->{input} = _event_hash($event);
  return;
}

sub _signing_key_for_fixture {
  my ($fixture, $keys) = @_;
  my $input = $fixture->{input};
  if (_is_delegated_removal_fixture($fixture)) {
    return $keys->{delegate};
  }
  if (_is_adapted_fixture_input($input)) {
    return $keys->{adapter};
  }
  return $keys->{native};
}

sub _rewritten_tags_for_signing {
  my ($input, $key, $events) = @_;
  my @tags = @{$input->{tags}};

  if ($input->{kind} == 37_800 && !_is_adapter_authority_event($input)) {
    @tags = _replace_tag_values(\@tags, 'd',           $key->pubkey_hex);
    @tags = _replace_tag_values(\@tags, 'overnet_oid', $key->pubkey_hex);
  }

  if ($input->{kind} == 7_801 && defined $events->{native}) {
    @tags = _replace_tag_values(\@tags, 'e', $events->{native}->id);
  }

  if (defined $events->{delegation}) {
    @tags = _replace_tag_values(\@tags, 'overnet_delegate', $events->{delegation}->id);
  }

  return @tags;
}

sub _replace_tag_values {
  my ($tags, $name, $value) = @_;
  my @rewritten;
  for my $tag (@{$tags}) {
    if ($tag->[0] eq $name) {
      push @rewritten, [$name, $value];
    } else {
      push @rewritten, $tag;
    }
  }
  return @rewritten;
}

sub _content_for_signing {
  my ($input, $json, $keys) = @_;
  if (!_is_delegation_event($input)) {
    return $input->{content};
  }

  my $content = $json->decode($input->{content});
  $content->{body}{delegate_pubkey} = $keys->{delegate}->pubkey_hex;
  return $json->encode($content);
}

sub _resolve_target_fixture {
  my ($fixture, $file, $events) = @_;
  if (!_context_has($fixture, 'target_fixture')) {
    return;
  }

  if ($fixture->{context}{target_fixture} ne 'valid-native-event') {
    croak "Unsupported target_fixture '$fixture->{context}{target_fixture}' in $file";
  }

  $fixture->{context}{target_event} = _event_hash($events->{native});

  if ($fixture->{context}{match_target_e}) {
    $fixture->{input}{tags} = [_replace_tag_values($fixture->{input}{tags}, 'e', $events->{native}->id),];
    delete $fixture->{context}{match_target_e};
  }

  delete $fixture->{context}{target_fixture};
  return;
}

sub _resolve_delegation_fixture {
  my ($fixture, $file, $events) = @_;
  if (!_context_has($fixture, 'delegation_fixture')) {
    return;
  }

  if ($fixture->{context}{delegation_fixture} ne 'valid-delegation-event') {
    croak "Unsupported delegation_fixture '$fixture->{context}{delegation_fixture}' in $file";
  }

  $fixture->{context}{delegation_event} = _event_hash($events->{delegation});

  if ($fixture->{context}{match_delegation_ref}) {
    $fixture->{input}{tags} =
      [_replace_tag_values($fixture->{input}{tags}, 'overnet_delegate', $events->{delegation}->id),];
    delete $fixture->{context}{match_delegation_ref};
  }

  delete $fixture->{context}{delegation_fixture};
  return;
}

sub _apply_delegate_pubkey_context {
  my ($fixture, $keys) = @_;
  if (!_context_has($fixture, 'use_delegate_pubkey')) {
    return;
  }

  $fixture->{input}{pubkey} = $keys->{delegate}->pubkey_hex;
  delete $fixture->{context}{use_delegate_pubkey};
  return;
}

# Builds a validly signed delegation context event whose kind or provenance
# is deliberately wrong, so fixtures can exercise the re-validation of a
# referenced delegation event (crypto passes; kind/provenance must still be
# checked). Signed with the native key so it matches the target event author.
sub _resolve_delegation_override {
  my ($fixture, $json, $keys, $spec_dir) = @_;
  my $override = ref $fixture->{context} eq 'HASH' ? $fixture->{context}{delegation_override} : undef;
  if (!(ref $override eq 'HASH')) {
    return;
  }

  my $template = _read_json_fixture($json, File::Spec->catfile($spec_dir, 'valid-delegation-event.json'));
  my $input    = $template->{input};
  my $content  = $json->decode($input->{content});
  $content->{body}{delegate_pubkey} = $keys->{delegate}->pubkey_hex;
  if (defined $override->{provenance}) {
    $content->{provenance} = {type => $override->{provenance}};
  }
  my $kind = defined $override->{kind} ? $override->{kind} : $input->{kind};

  my $event = $keys->{native}->create_event(
    kind       => $kind,
    content    => $json->encode($content),
    tags       => $input->{tags},
    created_at => $input->{created_at},
  );

  $fixture->{context}{delegation_event} = _event_hash($event);
  $fixture->{input}{tags} = [_replace_tag_values($fixture->{input}{tags}, 'overnet_delegate', $event->id),];
  delete $fixture->{context}{delegation_override};
  return;
}

sub _context_has {
  my ($fixture, $key) = @_;
  return 0 if !(ref $fixture->{context} eq 'HASH');
  return $fixture->{context}{$key} ? 1 : 0;
}

sub _is_delegated_removal_fixture {
  my ($fixture) = @_;
  return _context_has($fixture, 'delegation_fixture');
}

sub _is_adapted_fixture_input {
  my ($input) = @_;
  return $input->{content} =~ /"type" \s* : \s* "adapted"/smx ? 1 : 0;
}

sub _is_delegation_event {
  my ($input) = @_;
  my $event_type = _tag_value($input->{tags}, 'overnet_et');
  return 0 if !defined $event_type;
  return $event_type eq 'core.delegation' ? 1 : 0;
}

sub _is_adapter_authority_event {
  my ($input) = @_;
  my $event_type = _tag_value($input->{tags}, 'overnet_et');
  return 0 if !defined $event_type;
  return $event_type eq 'core.adapter_authority' ? 1 : 0;
}

sub _event_hash {
  my ($event) = @_;
  return {
    id         => $event->id,
    pubkey     => $event->pubkey,
    created_at => $event->created_at + 0,
    kind       => $event->kind + 0,
    tags       => $event->tags,
    content    => $event->content,
    sig        => $event->sig,
  };
}

sub _generate_native_event {
  my (%args)  = @_;
  my $fixture = _read_json_fixture($args{json}, $args{path});
  my $input   = $fixture->{input};

  return $args{key}->create_event(
    kind       => $input->{kind},
    content    => $input->{content},
    tags       => $input->{tags},
    created_at => $input->{created_at},
  );
}

sub _generate_delegation_event {
  my (%args)  = @_;
  my $fixture = _read_json_fixture($args{json}, $args{path});
  my $input   = $fixture->{input};
  my $content = $args{json}->decode($input->{content});
  $content->{body}{delegate_pubkey} = $args{delegate_key}->pubkey_hex;

  return $args{key}->create_event(
    kind       => $input->{kind},
    content    => $args{json}->encode($content),
    tags       => $input->{tags},
    created_at => $input->{created_at},
  );
}

sub _tag_value {
  my ($tags, $name) = @_;
  for my $tag (@{$tags // []}) {
    if (!(ref $tag eq 'ARRAY' && scalar @{$tag} >= 2)) {
      next;
    }
    return $tag->[1] if $tag->[0] eq $name;
  }
  return;
}

sub _spec_fixture_dir {
  my ($script_dir) = @_;
  my @candidates = (
    File::Spec->catdir($script_dir, File::Spec->updir, File::Spec->updir, 'spec', 'fixtures', 'core'),
    File::Spec->catdir(
      $script_dir, File::Spec->updir, File::Spec->updir, File::Spec->updir, 'spec', 'fixtures', 'core',
    ),
  );

  for my $candidate (@candidates) {
    return $candidate if -d $candidate;
  }

  return $candidates[0];
}

sub _read_json_fixture {
  my ($json, $path) = @_;
  return $json->decode(_read_file($path));
}

sub _read_file {
  my ($path) = @_;
  open my $file_handle, '<:encoding(UTF-8)', $path
    or croak "Can't read $path: $OS_ERROR";

  my $content = q{};
  while (defined(my $line = readline $file_handle)) {
    $content .= $line;
  }

  close $file_handle
    or croak "Can't close $path: $OS_ERROR";

  return $content;
}

sub _write_json_fixture {
  my (%args) = @_;
  open my $file_handle, '>:encoding(UTF-8)', $args{path}
    or croak "Can't write $args{path}: $OS_ERROR";

  print {$file_handle} $args{json}->encode($args{fixture})
    or croak "Can't write $args{path}: $OS_ERROR";

  close $file_handle
    or croak "Can't close $args{path}: $OS_ERROR";

  return;
}

sub _print_generated_count {
  my ($count, $out_dir) = @_;
  print {*STDOUT} "Generated $count fixtures in $out_dir\n"
    or croak "Can't write generation summary: $OS_ERROR";
  return;
}
