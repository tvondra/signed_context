/* signed_context */
CREATE OR REPLACE FUNCTION signed_context_get(key_name text)
    RETURNS text
    AS 'signed_context', 'signed_context_get'
    LANGUAGE C IMMUTABLE;

CREATE OR REPLACE FUNCTION signed_context_sign(key text, context text)
    RETURNS text
    AS 'signed_context', 'signed_context_sign'
    LANGUAGE C IMMUTABLE;

CREATE OR REPLACE FUNCTION signed_context_verify(context text)
    RETURNS bool
    AS 'signed_context', 'signed_context_verify'
    LANGUAGE C IMMUTABLE;

CREATE OR REPLACE FUNCTION signed_context_generate_keys(pkey out text, skey out text)
    RETURNS record
    AS 'signed_context', 'signed_context_generate_keys'
    LANGUAGE C IMMUTABLE;
