-- V35__users_email_lower_unique_index.sql
-- Closes an existing privilege-escalation hole (task-backlog item 148): AppUserDetailsService
-- grants ROLE_ADMIN via adminEmail.equalsIgnoreCase(user.getEmail()), but users.email only had a
-- case-SENSITIVE UNIQUE constraint, and AuthController's duplicate check was a plain (also
-- case-sensitive) existsByEmail. That let anyone register a case-variant of ADMIN_EMAIL (e.g.
-- "ADMIN@Example.com" next to an existing "admin@example.com") and be granted ROLE_ADMIN.
-- AuthController now lowercases every email before insert/lookup, but this index is the durable
-- DB-level backstop for rows written before that change, or by any future code path that forgets
-- to normalize.
--
-- Deliberately NOT a bare "CREATE UNIQUE INDEX ... (lower(email))" as the very first statement:
-- that alone would already refuse to create the index if case-insensitive duplicates exist, but
-- the failure would be a generic Postgres "could not create unique index" error that doesn't name
-- the colliding rows. Since this is a security-relevant migration, fail loudly and specifically
-- instead, and never silently pick a "winning" row and drop the other registration.
DO $$
DECLARE
    dup_count int;
BEGIN
    SELECT count(*) INTO dup_count
    FROM (
        SELECT lower(email)
        FROM users
        GROUP BY lower(email)
        HAVING count(*) > 1
    ) AS case_insensitive_duplicates;

    IF dup_count > 0 THEN
        RAISE EXCEPTION 'V35: % email address(es) in users collide case-insensitively; resolve the duplicates manually (merge or rename accounts) before this migration can proceed — see task-backlog item 148', dup_count;
    END IF;
END $$;

CREATE UNIQUE INDEX uq_users_email_lower ON users (lower(email));
