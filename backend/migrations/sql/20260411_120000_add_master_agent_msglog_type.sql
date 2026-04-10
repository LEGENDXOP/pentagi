-- +goose Up
-- +goose StatementBegin

-- Add 'master_agent' to the MSGLOG_TYPE enum.
-- PostgreSQL requires the rename-swap pattern for enum modification
-- (same pattern used in 20250331_200137_assistant_mode.sql).

CREATE TYPE MSGLOG_TYPE_NEW AS ENUM (
  'answer',
  'report',
  'thoughts',
  'browser',
  'terminal',
  'file',
  'search',
  'advice',
  'ask',
  'input',
  'done',
  'master_agent'
);

ALTER TABLE msglogs
    ALTER COLUMN type TYPE MSGLOG_TYPE_NEW USING type::text::MSGLOG_TYPE_NEW;

ALTER TABLE assistantlogs
    ALTER COLUMN type TYPE MSGLOG_TYPE_NEW USING type::text::MSGLOG_TYPE_NEW;

DROP TYPE MSGLOG_TYPE;

ALTER TYPE MSGLOG_TYPE_NEW RENAME TO MSGLOG_TYPE;

ALTER TABLE msglogs
    ALTER COLUMN type SET NOT NULL;

ALTER TABLE assistantlogs
    ALTER COLUMN type SET NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Remove 'master_agent' rows first to avoid cast errors
DELETE FROM msglogs WHERE type = 'master_agent';
DELETE FROM assistantlogs WHERE type = 'master_agent';

CREATE TYPE MSGLOG_TYPE_NEW AS ENUM (
  'answer',
  'report',
  'thoughts',
  'browser',
  'terminal',
  'file',
  'search',
  'advice',
  'ask',
  'input',
  'done'
);

ALTER TABLE msglogs
    ALTER COLUMN type TYPE MSGLOG_TYPE_NEW USING type::text::MSGLOG_TYPE_NEW;

ALTER TABLE assistantlogs
    ALTER COLUMN type TYPE MSGLOG_TYPE_NEW USING type::text::MSGLOG_TYPE_NEW;

DROP TYPE MSGLOG_TYPE;

ALTER TYPE MSGLOG_TYPE_NEW RENAME TO MSGLOG_TYPE;

ALTER TABLE msglogs
    ALTER COLUMN type SET NOT NULL;

ALTER TABLE assistantlogs
    ALTER COLUMN type SET NOT NULL;

-- +goose StatementEnd
