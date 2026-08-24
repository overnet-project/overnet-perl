use strictures 2;

use Test2::V0;

use Overnet::CommandBus;

subtest 'constructor defaults to empty handlers and middleware' => sub {
  my $bus = Overnet::CommandBus->new;
  is $bus->handlers, {}, 'handlers default to an empty hash';
  is $bus->middleware, [], 'middleware defaults to an empty array';

  my $from_hashref = Overnet::CommandBus->new({});
  is $from_hashref->handlers, {}, 'constructor accepts a hash reference';
};

subtest 'constructor rejects malformed arguments' => sub {
  like dies { Overnet::CommandBus->new('lonely') },
    qr/constructor arguments must be a hash or hash reference/,
    'odd argument list is rejected';

  like dies { Overnet::CommandBus->new(handlers => []) },
    qr/handlers must be a hash reference/,
    'non-hash handlers are rejected';

  like dies { Overnet::CommandBus->new(handlers => {'x.y' => 'not code'}) },
    qr/handler for method x\.y must be a code reference/,
    'non-code handler values are rejected';

  like dies { Overnet::CommandBus->new(middleware => {}) },
    qr/middleware must be an array reference/,
    'non-array middleware is rejected';

  like dies { Overnet::CommandBus->new(middleware => ['not code']) },
    qr/middleware entries must be code references/,
    'non-code middleware entries are rejected';
};

subtest 'constructor-supplied handlers and middleware are used and copied' => sub {
  my @order;
  my $handlers = {'echo.params' => sub { my ($method, $params) = @_; $params },};
  my $middleware =
    [sub { my ($method, $params, $context, $next) = @_; push @order, 'mw'; $next->() },];

  my $bus = Overnet::CommandBus->new(
    handlers   => $handlers,
    middleware => $middleware,
  );

  is $bus->dispatch('echo.params', {value => 1}), {value => 1}, 'constructor-supplied handler dispatches';
  is \@order, ['mw'], 'constructor-supplied middleware runs';

  $handlers->{'late.addition'} = sub { };
  ok !$bus->has_handler('late.addition'), 'mutating the original handlers hash does not affect the bus';
};

subtest 'register adds handlers and rejects bad input' => sub {
  my $bus = Overnet::CommandBus->new;

  my $returned = $bus->register('math.add', sub { my ($method, $params) = @_; $params->{a} + $params->{b} });
  ref_is $returned, $bus, 'register returns the bus for chaining';

  is $bus->dispatch('math.add', {a => 2, b => 3}), 5, 'registered handler dispatches';

  like dies {
    $bus->register('math.add', sub { })
  }, qr/handler already registered for method: math\.add/, 'duplicate registration is rejected';

  like dies {
    $bus->register(undef, sub { })
  }, qr/method is required/, 'undefined method name is rejected';
  like dies {
    $bus->register(q{}, sub { })
  }, qr/method is required/, 'empty method name is rejected';
  like dies {
    $bus->register([], sub { })
  }, qr/method is required/, 'reference method name is rejected';
  like dies { $bus->register('math.subtract', 'not code') },
    qr/handler must be a code reference/,
    'non-code handler is rejected';
};

subtest 'has_handler reports registration state' => sub {
  my $bus = Overnet::CommandBus->new;
  $bus->register('known.method', sub { });

  is $bus->has_handler('known.method'),   1, 'registered method is reported';
  is $bus->has_handler('unknown.method'), 0, 'unregistered method is reported';
  is $bus->has_handler(undef),            0, 'undefined method is reported unregistered';
  is $bus->has_handler([]),               0, 'reference method is reported unregistered';
};

subtest 'dispatch validates its arguments' => sub {
  my $bus = Overnet::CommandBus->new;
  $bus->register('known.method', sub { });

  like dies { $bus->dispatch(undef) }, qr/method is required/, 'undefined method is rejected';
  like dies { $bus->dispatch(q{}) },   qr/method is required/, 'empty method is rejected';
  like dies { $bus->dispatch({}) },    qr/method is required/, 'reference method is rejected';
  like dies { $bus->dispatch('known.method', 'not a hash') },
    qr/params must be a hash reference/,
    'non-hash params are rejected';
  like dies { $bus->dispatch('known.method', {}, 'not a hash') },
    qr/context must be a hash reference/,
    'non-hash context is rejected';
  like dies { $bus->dispatch('unknown.method') },
    qr/no handler registered for method: unknown\.method/,
    'unknown method is rejected';
};

subtest 'dispatch passes method, params, and context to the handler' => sub {
  my $bus = Overnet::CommandBus->new;
  my @seen;
  $bus->register('capture.args', sub { @seen = @_; {ok => 1} });

  my $params  = {key        => 'value'};
  my $context = {session_id => 'session-1'};
  my $result  = $bus->dispatch('capture.args', $params, $context);

  is $result, {ok => 1}, 'handler result is returned unchanged';
  is \@seen, ['capture.args', $params, $context], 'handler receives method, params, and context';

  $bus->register('capture.defaults', sub { @seen = @_; return });
  $bus->dispatch('capture.defaults');
  is $seen[1], {}, 'params default to an empty hash';
  is $seen[2], {}, 'context defaults to an empty hash';
};

subtest 'middleware runs in registration order around the handler' => sub {
  my $bus = Overnet::CommandBus->new;
  my @events;

  $bus->register('traced.method', sub { push @events, 'handler'; 'result' });
  $bus->add_middleware(
    sub {
      my ($method, $params, $context, $next) = @_;
      push @events, 'outer.enter';
      my $result = $next->();
      push @events, 'outer.exit';
      return $result;
    }
  );
  my $returned = $bus->add_middleware(
    sub {
      my ($method, $params, $context, $next) = @_;
      push @events, 'inner.enter';
      my $result = $next->();
      push @events, 'inner.exit';
      return $result;
    }
  );
  ref_is $returned, $bus, 'add_middleware returns the bus for chaining';

  is $bus->dispatch('traced.method'), 'result', 'result flows back through middleware';
  is \@events, ['outer.enter', 'inner.enter', 'handler', 'inner.exit', 'outer.exit'],
    'first added middleware is outermost';

  like dies { $bus->add_middleware('not code') }, qr/middleware must be a code reference/,
    'non-code middleware is rejected';
};

subtest 'middleware receives dispatch arguments and can enrich context' => sub {
  my $bus = Overnet::CommandBus->new;
  my @seen_by_middleware;
  my $seen_by_handler;

  $bus->register('context.reader', sub { my ($method, $params, $context) = @_; $seen_by_handler = $context; 1 });
  $bus->add_middleware(
    sub {
      my ($method, $params, $context, $next) = @_;
      @seen_by_middleware = ($method, $params);
      $context->{stamped} = 'yes';
      return $next->();
    }
  );

  my $params = {p => 1};
  $bus->dispatch('context.reader', $params, {session_id => 'session-2'});

  is \@seen_by_middleware, ['context.reader', $params], 'middleware receives the dispatched method and params';
  is $seen_by_handler, {session_id => 'session-2', stamped => 'yes'},
    'handler observes context changes made by middleware';
};

subtest 'middleware can short-circuit without calling the handler' => sub {
  my $bus            = Overnet::CommandBus->new;
  my $handler_called = 0;

  $bus->register('guarded.method', sub { $handler_called = 1; 'from handler' });
  $bus->add_middleware(
    sub {
      my ($method, $params, $context, $next) = @_;
      return 'from middleware';
    }
  );

  is $bus->dispatch('guarded.method'), 'from middleware', 'short-circuiting middleware supplies the result';
  is $handler_called,                  0,                 'handler is not called when middleware short-circuits';
};

subtest 'errors propagate through the middleware chain unchanged' => sub {
  my $bus = Overnet::CommandBus->new;

  my $structured = {code => 'protocol.invalid_params', message => 'bad params'};
  $bus->register('failing.structured', sub { CORE::die $structured });
  $bus->register('failing.string',     sub { CORE::die "plain failure\n" });
  $bus->add_middleware(sub { my ($method, $params, $context, $next) = @_; $next->() });

  my $error = dies { $bus->dispatch('failing.structured') };
  ref_is $error, $structured, 'structured hash errors pass through by reference';

  like dies { $bus->dispatch('failing.string') }, qr/\Aplain failure\n\z/, 'string errors pass through unchanged';
};

subtest 'normalize_error shapes errors into structured hashes' => sub {
  my $structured = {code => 'runtime.permission_denied', message => 'denied'};
  ref_is +Overnet::CommandBus->normalize_error($structured, code => 'fallback.code'),
    $structured, 'conforming structured errors pass through by reference';

  is +Overnet::CommandBus->normalize_error("plain failure\n", code => 'fallback.code'),
    {code => 'fallback.code', message => 'plain failure'},
    'string errors are chomped and wrapped with the fallback code';

  my $incomplete = {message => 'no code here'};
  my $normalized = Overnet::CommandBus->normalize_error($incomplete, code => 'fallback.code');
  is $normalized->{code}, 'fallback.code', 'hashes missing code are wrapped';
  ok !ref($normalized->{message}), 'wrapped non-conforming errors carry a string message';

  like dies { Overnet::CommandBus->normalize_error('x') }, qr/code is required/,
    'normalize_error requires a fallback code';
};

subtest 'error_normalizer middleware guarantees structured errors' => sub {
  my $bus =
    Overnet::CommandBus->new(middleware => [Overnet::CommandBus->error_normalizer(code => 'program.operation_failed')],
    );

  my $structured = {code => 'protocol.invalid_params', message => 'bad params'};
  $bus->register('failing.structured', sub { CORE::die $structured });
  $bus->register('failing.string',     sub { CORE::die "backend exploded\n" });
  $bus->register('passing.method',     sub { {ok => 1} });

  ref_is dies { $bus->dispatch('failing.structured') }, $structured,
    'structured errors pass through the normalizer unchanged';

  is dies { $bus->dispatch('failing.string') },
    {code => 'program.operation_failed', message => 'backend exploded'},
    'string errors leave the bus as structured errors';

  is $bus->dispatch('passing.method'), {ok => 1}, 'successful results are unaffected';

  like dies { Overnet::CommandBus->error_normalizer() }, qr/code is required/,
    'error_normalizer requires a fallback code';
};

subtest 'middleware can observe and translate errors' => sub {
  my $bus = Overnet::CommandBus->new;

  $bus->register('failing.method', sub { CORE::die {code => 'inner.error', message => 'inner'} });
  $bus->add_middleware(
    sub {
      my ($method, $params, $context, $next) = @_;
      my $result;
      my $error;
      eval {
        $result = $next->();
        1;
      } or $error = $@;
      return {caught => $error->{code}} if $error;
      return $result;
    }
  );

  is $bus->dispatch('failing.method'), {caught => 'inner.error'}, 'middleware can catch and translate handler errors';
};

done_testing;
