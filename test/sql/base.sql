\set ECHO none

-- disable the notices for the create script (shell types etc.)
SET client_min_messages = 'WARNING';
\i sql/signed_context--1.0.0.sql
SET client_min_messages = 'NOTICE';

\set ECHO all

-- generate new keypair
SELECT * FROM signed_context_generate_keys() \gset

-- generate a valid signed context
SELECT signed_context_sign(:'skey', 'a:1:b:2:c:3') AS context \gset

-- try to set it without the public key installed
SET signed_context.context = :'context';

-- set it for the database
ALTER DATABASE :DBNAME SET signed_context.key = :'pkey';

-- reconnect, to activate the database key
\connect

-- verify the context (function call forces loading the library, which
-- is what sets the check/assign hooks we need)
SELECT signed_context_verify(:'context');

-- some bogus contexts first
SET signed_context.context = 'blahblah';
SET signed_context.context = 'foo:bar';
SET signed_context.context = 'foo:bar:baz';
SHOW signed_context.context;

-- now the correctly signed context
SET signed_context.context = :'context';

SHOW signed_context.context;

-- existing key
SELECT signed_context_get('a');

-- missing key
SELECT signed_context_get('d');
