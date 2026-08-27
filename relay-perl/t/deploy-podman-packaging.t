use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "Can't open $path: $!";
  local $/ = undef;
  return <$fh>;
}

my $code_root   = File::Spec->catdir($FindBin::Bin, '..');
my $podman_dir  = File::Spec->catdir($code_root, 'deploy', 'podman');
my $containerfile = File::Spec->catfile($podman_dir, 'Containerfile');
my $container_unit = File::Spec->catfile($podman_dir, 'overnet-relay.container');
my $volume_unit    = File::Spec->catfile($podman_dir, 'overnet-relay.volume');
my $readme         = File::Spec->catfile($podman_dir, 'README.md');
my $relay_readme   = File::Spec->catfile($code_root, 'README.md');
my $entrypoint     = File::Spec->catfile($podman_dir, 'entrypoint.pl');
my $smoke_test     = File::Spec->catfile($podman_dir, 'smoke-test.sh');
my $quadlet_check  = File::Spec->catfile($podman_dir, 'quadlet-check.sh');
my $tag_digest     = File::Spec->catfile($podman_dir, 'registry-tag-digest.sh');
my $publish_image  = File::Spec->catfile($podman_dir, 'publish-image.sh');
my $validate_sbom  = File::Spec->catfile($podman_dir, 'validate-sbom.pl');
my $workflow = File::Spec->catfile($code_root, '..', '.github', 'workflows', 'relay-container.yml');
my $dependabot = File::Spec->catfile($code_root, '..', '.github', 'dependabot.yml');
my $dockerignore = File::Spec->catfile($code_root, '..', '.dockerignore');
my $containerignore = File::Spec->catfile($code_root, '..', '.containerignore');

ok -f $containerfile,  'Containerfile exists';
ok -f $container_unit, 'Quadlet .container unit exists';
ok -f $volume_unit,    'Quadlet .volume unit exists';
ok -f $readme,         'podman deploy README exists';
ok -f $entrypoint,     'minimal image role entrypoint exists';
ok -f $dockerignore,   'Docker build-context filter exists';
ok -f $containerignore, 'Podman build-context filter exists';

for my $ignore_file ($dockerignore, $containerignore) {
  next if !-f $ignore_file;
  my $ignore_text = _slurp($ignore_file);
  like $ignore_text, qr{^relay-perl/deploy/podman/\*$}mx,
    "$ignore_file excludes deployment metadata from early COPY layers";
  like $ignore_text, qr{^!relay-perl/deploy/podman/entrypoint\.pl$}mx,
    "$ignore_file retains the runtime role entrypoint";
  like $ignore_text, qr{^relay-perl/t/registry-publication\.t$}mx,
    "$ignore_file excludes CI-only registry publication tests";
  like $ignore_text, qr{^relay-perl/t/sbom-validation\.t$}mx,
    "$ignore_file excludes CI-only SBOM validation tests";
}

# The CI verification (build + smoke run + Quadlet check) must be present and
# runnable. These assert existence and wiring, not the scripts' contents, so the
# checks survive edits to how the verification works.
ok -f $smoke_test && -s $smoke_test,    'smoke-test script exists and is non-empty';
ok -x $smoke_test,                      'smoke-test script is executable';
ok -f $quadlet_check && -s $quadlet_check, 'quadlet-check script exists and is non-empty';
ok -x $quadlet_check,                   'quadlet-check script is executable';
ok -f $tag_digest && -s $tag_digest,    'registry tag lookup script exists and is non-empty';
ok -x $tag_digest,                      'registry tag lookup script is executable';
ok -f $publish_image && -s $publish_image,
  'write-once publication script exists and is non-empty';
ok -x $publish_image,                   'write-once publication script is executable';
ok -f $validate_sbom && -s $validate_sbom,
  'SPDX SBOM validator exists and is non-empty';
ok -x $validate_sbom,                   'SPDX SBOM validator is executable';
ok -f $workflow,                        'container-build workflow exists';
ok -f $dependabot,                       'dependency-update configuration exists';

my $workflow_text = _slurp($workflow);
my $publish_image_text = _slurp($publish_image);
like $workflow_text, qr{apt-get\s+install[^\n]*\bpodman\b}mx,
  'workflow installs the complete Podman package for Quadlet validation';
like $workflow_text, qr{podman\s+build}mx,
  'workflow builds the image';
like $workflow_text, qr{\bContainerfile\b}mx,
  'workflow builds from the Containerfile';
like $workflow_text, qr{smoke-test\.sh}mx,
  'workflow runs the smoke test';
like $workflow_text, qr{quadlet-check\.sh}mx,
  'workflow runs the Quadlet check';
like $workflow_text, qr{^\s+schedule:\s*$}mx,
  'workflow rebuilds the image on a schedule';
like $workflow_text, qr{^\s+-\s+cron:\s*['"][^'"]+['"]\s*$}mx,
  'workflow has a scheduled rebuild cadence';
like $workflow_text,
  qr{publish:\s+.*?if:\s*>-\s+.*?github\.event_name\s*==\s*'push'.*?github\.ref\s*==\s*'refs/heads/main'}msx,
  'workflow publishes only for pushes to main';
like $workflow_text, qr{^\s+environment:\s+quay-publish\s*$}mx,
  'publishing job uses the protected Quay environment';
like $workflow_text, qr{^\s+group:\s+relay-container-publish\s*$}mx,
  'publishing job has a dedicated concurrency group';
like $workflow_text, qr{^\s+cancel-in-progress:\s+true\s*$}mx,
  'newer main builds cancel stale publication jobs';
like $workflow_text, qr{\$\{\{\s*vars\.QUAY_USERNAME\s*\}\}}mx,
  'workflow reads the robot username from an environment variable';
like $workflow_text, qr{\$\{\{\s*secrets\.QUAY_TOKEN\s*\}\}}mx,
  'workflow reads the robot token from an environment secret';
like $workflow_text,
  qr{podman\s+login\s+quay\.io.*?--username.*?--password-stdin}msx,
  'workflow sends the Quay token to podman through standard input';
unlike $workflow_text, qr{podman\s+login[^\n]*--password(?:=|\s)}mx,
  'workflow never places the Quay token in a login argument';
like $workflow_text, qr{tag="sha-\$\{GITHUB_SHA\}"}mx,
  'workflow resolves a commit-qualified full-commit tag';
like $publish_image_text, qr{sha_ref="\$\{repository\}:\$\{tag\}"}mx,
  'publication helper constructs the resolved commit tag';
like $workflow_text, qr{id:\s+commit-image}mx,
  'workflow resolves the commit image before building';
like $workflow_text, qr{registry-tag-digest\.sh}mx,
  'workflow checks whether the commit tag already exists';
like $workflow_text,
  qr{podman\s+pull\s+"\$repository\@\$existing_digest"}mx,
  'workflow retrieves an existing commit image by immutable digest';
like $workflow_text,
  qr{org\.opencontainers\.image\.revision.*?org\.opencontainers\.image\.version}msx,
  'workflow verifies the source labels of a reused commit image';
like $workflow_text,
  qr{if:\s+steps\.commit-image\.outputs\.exists\s+!=\s+'true'}mx,
  'workflow builds only when the commit tag is absent';
like $workflow_text, qr{--build-arg\s+VCS_REF="\$GITHUB_SHA"}mx,
  'published image records the full source revision';
like $workflow_text, qr{--build-arg\s+VERSION="sha-\$\{GITHUB_SHA\}"}mx,
  'published image records its commit-qualified version';
like $publish_image_text, qr{main_ref="\$\{repository\}:main"}mx,
  'publication helper updates the documented main tag';
unlike $workflow_text . $publish_image_text,
  qr{quay\.io/overnet/relay:latest}mx,
  'publication path never uses an ambiguous latest tag';
like $publish_image_text, qr{podman\s+push\s+--digestfile\b}mx,
  'publication helper records each pushed image digest';
like $workflow_text, qr{publish-image\.sh}mx,
  'workflow delegates write-once publication to the tested helper';
like $workflow_text, qr{GITHUB_STEP_SUMMARY}mx,
  'workflow reports the immutable published image reference';
like $workflow_text, qr{podman\s+logout\b[^\n]*\bquay\.io}mx,
  'workflow removes registry credentials after publishing';
is scalar(() = $workflow_text =~ m{uses:\s+anchore/sbom-action\@[0-9a-f]{40}\s+\#\s+v0\.24\.0}gmx),
  2, 'both workflow paths generate SBOMs with the pinned Syft action';
like $workflow_text, qr{podman\s+save\s+--format\s+oci-archive}mx,
  'non-publishing builds scan an OCI archive of the tested local image';
like $workflow_text, qr{image:\s+oci-archive:}mx,
  'non-publishing SBOM generation explicitly scans the OCI archive';
like $workflow_text,
  qr{image:\s+registry:quay\.io/overnet/relay\@\$\{\{\s*needs\.publish\.outputs\.image-digest\s*\}\}}mx,
  'published SBOM generation scans the immutable registry digest';
is scalar(() = $workflow_text =~ m{format:\s+spdx-json\s*$}gmx), 2,
  'both workflow paths emit SPDX JSON';
is scalar(() = $workflow_text =~ m{validate-sbom\.pl\s+[^\n]*\.spdx\.json}gmx), 3,
  'both generators and the attestation job validate SPDX documents';
is scalar(() = $workflow_text =~ m{upload-artifact:\s+false\s*$}gmx), 2,
  'the third-party generator cannot upload unvalidated artifacts';
is scalar(() = $workflow_text =~ m{uses:\s+actions/upload-artifact\@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\s+\#\s+v7\.0\.1}gmx),
  2, 'both validated SBOMs use the pinned first-party artifact uploader';
like $workflow_text,
  qr{uses:\s+actions/download-artifact\@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c\s+\#\s+v8\.0\.1}mx,
  'attestation uses the pinned first-party artifact downloader';
like $workflow_text,
  qr{permissions:\s+.*?id-token:\s+write\s+.*?attestations:\s+write\s+.*?artifact-metadata:\s+write}msx,
  'publishing job grants the permissions required for signed SBOM metadata';
like $workflow_text,
  qr{uses:\s+actions/attest\@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6\s+\#\s+v4\.2\.0}mx,
  'workflow uses the pinned current GitHub attestation action';
like $workflow_text, qr{subject-name:\s+quay\.io/overnet/relay\s*$}mx,
  'SBOM attestation subject is the untagged fully-qualified image name';
like $workflow_text,
  qr{subject-digest:\s+\$\{\{\s*needs\.publish\.outputs\.image-digest\s*\}\}}mx,
  'SBOM attestation is bound to the published digest';
like $workflow_text, qr{subject-version:\s+sha-\$\{\{\s*github\.sha\s*\}\}}mx,
  'linked artifact metadata records the full source version';
like $workflow_text, qr{sbom-path:\s+[^\n]*\.spdx\.json\s*$}mx,
  'SBOM attestation consumes the validated SPDX document';
like $workflow_text, qr{push-to-registry:\s+true\s*$}mx,
  'SBOM attestation is published to Quay';
like $workflow_text, qr{create-storage-record:\s+true\s*$}mx,
  'workflow publishes linked artifact metadata';
like $workflow_text,
  qr{gh\s+attestation\s+verify\s+.*?--bundle-from-oci.*?--predicate-type\s+https://spdx\.dev/Document/v2\.3}msx,
  'workflow verifies the Quay-hosted SPDX attestation';
like $workflow_text,
  qr{--signer-workflow\s+overnet-project/overnet-perl/\.github/workflows/relay-container\.yml}mx,
  'registry verification constrains the signer workflow';
like $workflow_text, qr{--source-ref\s+refs/heads/main}mx,
  'registry verification constrains the source branch';
like $workflow_text, qr{auths\s*=>\s*\{"quay\.io"\s*=>\s*\{auth\s*=>\s*\$auth\}\}}mx,
  'attestation credentials use the Docker configuration consumed by the action';
like $workflow_text,
  qr{REGISTRY_AUTH_FILE:\s+\$\{\{\s*runner\.temp\s*\}\}/podman-auth\.json}mx,
  'image publication uses an isolated Podman credential file';
like $workflow_text,
  qr{Remove image-publishing credentials.*?rm\s+-f\s+"\$RUNNER_TEMP/podman-auth\.json".*?Generate the published SPDX SBOM}ms,
  'publishing credentials are removed before the third-party SBOM action runs';
like $workflow_text, qr{rm\s+-f\s+"\$HOME/\.docker/config\.json"}mx,
  'workflow removes the shared registry credential file';

my ($sbom_job_text) = $workflow_text =~
  m{^  sbom:\s*\n(.*?)(?=^  [a-z][a-z0-9-]*:\s*\n)}ms;
ok defined $sbom_job_text, 'published SBOM generation has a dedicated job';
if (defined $sbom_job_text) {
  unlike $sbom_job_text, qr{secrets\.}mx,
    'third-party SBOM generation receives no repository secrets';
  unlike $sbom_job_text, qr{id-token:\s+write}mx,
    'third-party SBOM generation receives no OIDC permission';
  unlike $sbom_job_text, qr{attestations:\s+write}mx,
    'third-party SBOM generation cannot create attestations';
}
my ($attest_job_text) = $workflow_text =~
  m{^  attest-sbom:\s*\n(.*)\z}ms;
ok defined $attest_job_text, 'SBOM attestation has a dedicated job';
if (defined $attest_job_text) {
  unlike $attest_job_text, qr{anchore/sbom-action}mx,
    'privileged attestation job runs no third-party SBOM action';
  like $attest_job_text, qr{Revalidate the downloaded SPDX SBOM}m,
    'privileged job revalidates the transferred SBOM';
}

if (-f $dependabot) {
  my $dependabot_text = _slurp($dependabot);
  like $dependabot_text, qr{package-ecosystem:\s*["']docker["']}mx,
    'Dependabot monitors container base images';
  like $dependabot_text,
    qr{directory:\s*["']/relay-perl/deploy/podman["']}mx,
    'Dependabot scans the directory containing the relay Containerfile';
  like $dependabot_text, qr{interval:\s*["']weekly["']}mx,
    'Dependabot checks the relay base image weekly';
}

my $containerfile_text = _slurp($containerfile);
unlike $containerfile_text, qr{docker\.io}mx,
  'Containerfile never uses Docker Hub';
unlike $containerfile_text, qr{^FROM\s+\S+:latest(?:\@|\s)}mx,
  'Containerfile never uses a mutable latest base tag';
unlike $containerfile_text, qr{^FROM\s+quay\.io/fedora/fedora-minimal\b}mx,
  'Containerfile does not use the Fedora Quay mirror for its base';
my ($fedora_release) = $containerfile_text =~
  qr{^FROM\s+registry\.fedoraproject\.org/fedora-minimal:(\d+)\@sha256:[0-9a-f]{64}\s+AS\s+builder$}mx;
ok defined $fedora_release,
  'Containerfile pins Fedora Minimal from Fedora registry by numeric release and digest';
unlike $containerfile_text, qr{^ARG\s+FEDORA_(?:VERSION|MINIMAL_IMAGE)\b}mx,
  'Containerfile does not duplicate the Fedora release in build arguments';
like $containerfile_text,
  qr{FEDORA_VERSION="\$\(rpm\s+-E\s+'%\{fedora\}'\)"}mx,
  'runtime assembly derives the Fedora release from RPM metadata';
like $containerfile_text, qr{--releasever="\$\{FEDORA_VERSION\}"}mx,
  'runtime package installation uses the derived Fedora release';
like $containerfile_text, qr{^FROM\s+scratch$}mx,
  'Containerfile emits a scratch-based final runtime';
like $containerfile_text, qr{COPY\s+core-perl\b}mx,
  'builder copies the sibling core-perl checkout';
like $containerfile_text, qr{COPY\s+relay-perl\b}mx,
  'builder copies the relay-perl checkout';
like $containerfile_text, qr{--installdeps\b}mx,
  'Containerfile installs CPAN prerequisites';
like $containerfile_text,
  qr{cpanm\s+--installdeps\s+/build/core-perl}mx,
  'builder tests the normal core dependency installation';
like $containerfile_text,
  qr{cpanm\s+--notest\s+--local-lib-contained\s+/runtime-local}mx,
  'tested dependencies are reinstalled into an isolated runtime tree';
like $containerfile_text, qr{\bgit-core\b}mx,
  'builder includes git for dependency conformance tests';
like $containerfile_text, qr{Crypt-PK-ECC-Schnorr}mx,
  'Containerfile pre-installs the unindexed Schnorr dist Net::Nostr::Core needs';
like $containerfile_text, qr{\bgmp-devel\b}mx,
  'builder installs gmp-devel for Math::GMPz';
like $containerfile_text, qr{dnf5\s+--installroot=/runtime-root}mx,
  'builder assembles an explicit runtime package closure';
unlike $containerfile_text, qr{^\s*perl-core\b}mx,
  'runtime does not install Fedora full-core Perl metapackage';
like $containerfile_text, qr{^\s*perl-interpreter\s*\\?$}mx,
  'runtime installs the minimal Fedora Perl interpreter package';
like $containerfile_text, qr{^\s*perl-Net-SSLeay\s*\\?$}mx,
  'runtime installs the TLS XS binding required by IO::Socket::SSL';
for my $runtime_perl_package (
  qw(
    perl-Compress-Raw-Zlib
    perl-Digest-SHA
    perl-English
    perl-experimental
    perl-File-Copy
    perl-FindBin
    perl-IO-Compress
    perl-JSON-PP
    perl-lib
    perl-Math-BigInt
    perl-Params-Util
    perl-subs
    perl-version
  )
) {
  like $containerfile_text,
    qr{^\s*\Q$runtime_perl_package\E\s*\\?$}mx,
    "runtime explicitly installs loaded Fedora module package $runtime_perl_package";
}
like $containerfile_text, qr{--setopt=install_weak_deps=False}mx,
  'runtime package closure excludes weak dependencies';
like $containerfile_text, qr{--no-docs}mx,
  'runtime package closure excludes packaged documentation';
like $containerfile_text, qr{^FROM\s+builder\s+AS\s+runtime-assembler$}mx,
  'runtime assembly is isolated from the tested builder stage';
like $containerfile_text,
  qr{COPY\s+--from=runtime-assembler\s+/runtime-root/\s+/}mx,
  'final image receives only the assembled runtime root';
like $containerfile_text,
  qr{cp\s+-a\s+/runtime-local/\.\s+/runtime-root/opt/overnet/perl5/}mx,
  'final runtime receives the isolated CPAN and Overnet library tree';
like $containerfile_text,
  qr{auto/share/dist/Alien-cmake3}mx,
  'runtime assembly removes the build-only Alien::cmake3 payload';
like $containerfile_text,
  qr{rpm\s+--root\s+/runtime-root\s+--erase\b.*\bbash\b}msx,
  'runtime assembly removes shell and utility RPMs after installation';
like $containerfile_text, qr{test\s+!\s+-e\s+/runtime-root/usr/bin/sh}mx,
  'runtime assembly asserts that no shell remains';
unlike $containerfile_text,
  qr{cp\s+-a\s+/usr/local/\.\s+/runtime-root/}mx,
  'final runtime does not copy the builder test installation';
like $containerfile_text, qr{ENTRYPOINT\s+\["/usr/bin/perl",\s*"/opt/overnet/bin/entrypoint\.pl"\]}mx,
  'final image uses a direct Perl role dispatcher';
like $containerfile_text, qr{^USER\s+10001:10001$}mx,
  'final image runs as a numeric unprivileged identity';
like $containerfile_text, qr{^EXPOSE\s+7447\s+7448$}mx,
  'final image exposes both relay role ports';

my ($final_stage) = $containerfile_text =~ /(^FROM\s+scratch\b.*)\z/msx;
ok defined $final_stage, 'final scratch stage is identifiable';
unlike $final_stage, qr{\b(?:dnf5|microdnf|gcc|make|cpanm)\b}mx,
  'final stage does not install or invoke build and package tools';
unlike $final_stage, qr{^VOLUME\b}mx,
  'shared multi-role image does not create a role-specific anonymous volume';

my $entrypoint_text = _slurp($entrypoint);
like $entrypoint_text, qr{\brelay\b}mx,
  'entrypoint supports the generic relay role';
like $entrypoint_text, qr{\bauthority\b}mx,
  'entrypoint supports the authority relay role';
unlike $entrypoint_text, qr{/bin/(?:ba)?sh}mx,
  'entrypoint does not depend on a shell';

my $container_unit_text = _slurp($container_unit);
like $container_unit_text, qr{^\[Container\]}mx,
  'Quadlet unit declares a [Container] section';
like $container_unit_text, qr{^Image=}mx,
  'Quadlet unit sets an image';
like $container_unit_text, qr{^Image=quay\.io/overnet/relay:main$}mx,
  'generic relay Quadlet uses the official published image';
like $container_unit_text, qr{^Pull=missing$}mx,
  'generic relay Quadlet does not replace an existing image implicitly';
like $container_unit_text, qr{^Volume=overnet-relay\.volume:}mx,
  'Quadlet unit mounts the store volume by the .volume unit file name';
like $container_unit_text, qr{^PublishPort=127\.0\.0\.1:7447:7447}mx,
  'Quadlet unit publishes the listener on loopback by default';
like $container_unit_text, qr{--store-file\s+/var/lib/overnet/relay/store\.json}mx,
  'Quadlet unit points the store file at the mounted volume';
like $container_unit_text, qr{--health-file\s+/var/lib/overnet/relay/health\.json}mx,
  'Quadlet unit configures a health file on the mounted volume';
like $container_unit_text, qr{^HealthCmd=}mx,
  'Quadlet unit defines a health check';
like $container_unit_text,
  qr{^HealthCmd=\["/usr/bin/perl","-MIO::Socket::INET","-e",}mx,
  'generic relay uses an exec-form health check without a shell';

for my $setting (
  'ReadOnly=true',
  'ReadOnlyTmpfs=true',
  'NoNewPrivileges=true',
  'DropCapability=all',
  'PidsLimit=256',
) {
  like $container_unit_text, qr{^\Q$setting\E$}mx,
    "generic relay Quadlet sets $setting";
}

my $volume_unit_text = _slurp($volume_unit);
like $volume_unit_text, qr{^\[Volume\]}mx,
  'Quadlet volume unit declares a [Volume] section';
like $volume_unit_text, qr{^VolumeName=overnet-relay-store}mx,
  'Quadlet volume unit names the store volume';

# The store path baked into the Containerfile CMD, the Quadlet Exec= line, and
# the volume mount must agree, or the store would not persist.
like $containerfile_text, qr{/var/lib/overnet/relay}mx,
  'Containerfile store path matches the mounted volume path';
like $container_unit_text, qr{Volume=overnet-relay\.volume:/var/lib/overnet/relay:}mx,
  'Quadlet mount path matches the configured store path';

my $readme_text = _slurp($readme);
my $relay_readme_text = _slurp($relay_readme);
like $relay_readme_text, qr{deploy/podman/README\.md}mx,
  'relay README links to the container deployment guide';
like $readme_text, qr{podman\s+build}mx,
  'README documents building the image';
like $readme_text, qr{podman`\s+4\.9\+}mx,
  'README states the verified minimum Podman version';
like $readme_text, qr{\.config/containers/systemd}mx,
  'README documents the rootless Quadlet install path';
like $readme_text, qr{Fedora\s+Minimal.*pinned|pinned.*Fedora\s+Minimal}imsx,
  'README documents the pinned Fedora Minimal builder policy';
like $readme_text, qr{registry\.fedoraproject\.org/fedora-minimal}mx,
  'README identifies Fedora authoritative image registry';
unlike $readme_text, qr{(?:fedora/fedora-minimal:|\bFedora\s+)\d+}imx,
  'README does not duplicate the Containerfile Fedora release';
like $readme_text, qr{Dependabot.*weekly}msx,
  'README documents weekly Fedora base update proposals';
like $readme_text, qr{never\s+uses?\s+`latest`}mx,
  'README rejects mutable latest base tags';
like $readme_text, qr{starts\s+from\s+`scratch`}mx,
  'README documents the scratch runtime image';
like $readme_text, qr{drop\s+every\s+Linux\s+capability}mx,
  'README documents the Quadlet capability boundary';
like $readme_text, qr{compiler,\s+build\s+tools,\s+shell,}mx,
  'README documents the shell-free runtime';
like $readme_text, qr{health\s+checks\s+use\s+JSON\s+exec\s+form}mx,
  'README documents direct health-check execution';
like $readme_text, qr{quay\.io/overnet/relay}mx,
  'README documents the official published image';
like $readme_text, qr{sha-<full-git-commit>}mx,
  'README documents commit-qualified image tags';
like $readme_text, qr{does\s+not\s+publish\s+`latest`}mx,
  'README documents that latest is not published';
like $readme_text, qr{Image=quay\.io/overnet/relay\@sha256:}mx,
  'README documents digest-pinned production deployment';
like $readme_text, qr{write-once}imx,
  'README documents the CI-enforced commit-tag policy';
like $readme_text, qr{Quay\.io.*does\s+not.*immutab}imsx,
  'README distinguishes CI policy from registry-enforced immutability';
like $readme_text, qr{SPDX\s+2\.3}mx,
  'README documents the published SBOM format';
like $readme_text, qr{gh\s+attestation\s+verify}mx,
  'README documents SBOM signature verification';
like $readme_text, qr{--predicate-type\s+https://spdx\.dev/Document/v2\.3}mx,
  'README verifies the SPDX predicate explicitly';
like $readme_text, qr{--bundle-from-oci}mx,
  'README documents registry-backed attestation verification';

# Setting VolumeName= makes podman use that name verbatim (no systemd- prefix),
# so the README must inspect the volume by exactly that name and must not refer
# to the prefixed default name the unit does not produce.
my ($volume_name) = $volume_unit_text =~ /^VolumeName=(\S+)/mx;
ok $volume_name, 'volume unit sets an explicit VolumeName';
like $readme_text, qr{podman\s+volume\s+inspect\s+\Q$volume_name\E\b}mx,
  'README inspects the volume by its actual (unprefixed) name';
unlike $readme_text, qr{systemd-\Q$volume_name\E}mx,
  'README does not reference the systemd- prefixed name VolumeName suppresses';

# --- authority relay: a second flavor served from the same image -------------

my $authority_unit = File::Spec->catfile($podman_dir, 'overnet-authority-relay.container');
my $authority_vol  = File::Spec->catfile($podman_dir, 'overnet-authority-relay.volume');
my $authority_bin  = File::Spec->catfile($code_root, 'bin', 'overnet-authority-relay.pl');

ok -f $authority_unit, 'authority relay Quadlet .container unit exists';
ok -f $authority_vol,  'authority relay Quadlet .volume unit exists';
ok -f $authority_bin,  'authority relay entrypoint exists';

my $authority_unit_text = _slurp($authority_unit);
like $authority_unit_text, qr{^Image=quay\.io/overnet/relay:main$}mx,
  'authority relay reuses the generic relay image';
like $authority_unit_text, qr{^Pull=missing$}mx,
  'authority relay does not replace an existing image implicitly';
unlike $authority_unit_text, qr{^PodmanArgs=}mx,
  'authority relay does not override the hardened image entrypoint';
like $authority_unit_text, qr{^Exec=authority\b}mx,
  'authority relay selects the authority role through the image entrypoint';
like $authority_unit_text, qr{^Volume=overnet-authority-relay\.volume:/var/lib/overnet/authority-relay:}mx,
  'authority relay mounts its own store volume by the .volume unit file name';
like $authority_unit_text, qr{--store-file\s+/var/lib/overnet/authority-relay/}mx,
  'authority relay keeps its store on the mounted volume';
like $authority_unit_text, qr{^HealthCmd=}mx,
  'authority relay defines a health check';
like $authority_unit_text,
  qr{^HealthCmd=\["/usr/bin/perl","-MIO::Socket::INET","-e",}mx,
  'authority relay uses an exec-form health check without a shell';

for my $setting (
  'ReadOnly=true',
  'ReadOnlyTmpfs=true',
  'NoNewPrivileges=true',
  'DropCapability=all',
  'PidsLimit=256',
) {
  like $authority_unit_text, qr{^\Q$setting\E$}mx,
    "authority relay Quadlet sets $setting";
}

my $authority_vol_text = _slurp($authority_vol);
like $authority_vol_text, qr{^VolumeName=overnet-authority-relay-store}mx,
  'authority relay volume unit names its store volume';

# Both role scripts must reach the builder so the direct image dispatcher can
# install them in the final image.
like $containerfile_text, qr{COPY\s+relay-perl\b}mx,
  'Containerfile copies the relay tree that carries both entrypoints';

# The container-build workflow must exercise the authority relay too.
like $workflow_text, qr{overnet-authority-relay\.container}mx,
  'workflow smoke-tests the authority relay unit';

done_testing;
