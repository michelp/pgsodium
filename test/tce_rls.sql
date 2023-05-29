\if :serverkeys
\if :pg15

CREATE TABLE public.foo(
  secret text,
  visible bool DEFAULT false
);

ALTER TABLE public.foo ENABLE ROW LEVEL SECURITY;

CREATE POLICY foo_visible ON foo TO pgsodium_keyholder
    USING (visible);

-- Create a key id to use in the tests below
SELECT id AS secret_key_id FROM pgsodium.create_key('aead-det') \gset

SELECT lives_ok(
  format($test$
         SECURITY LABEL FOR pgsodium ON COLUMN public.foo.secret
         IS 'ENCRYPT WITH KEY ID %s SECURITY INVOKER'
         $test$, :'secret_key_id'),
  'can label column for encryption with security invoker');

INSERT INTO public.foo VALUES ('yes', true);
INSERT INTO public.foo VALUES ('no', false);

CREATE ROLE rls_bobo with login password 'foo';
GRANT ALL ON public.foo TO rls_bobo;

SELECT lives_ok(
  $test$
  SECURITY LABEL FOR pgsodium ON ROLE rls_bobo is 'ACCESS public.foo'
  $test$,
  'can label roles ACCESS for RLS');

SELECT pgsodium.update_masks(); -- labeling roles doesn't fire event trigger

set role rls_bobo;

SET client_min_messages TO WARNING;

SELECT results_eq($$SELECT decrypted_secret = 'yes' from public.decrypted_foo$$,
    $$VALUES (true)$$,
    'can see updated decrypted view but not excluded row');

reset role;
\endif
\endif
