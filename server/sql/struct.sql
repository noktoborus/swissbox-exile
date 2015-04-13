/*	vim: synta=pgsql
*/

DROP TABLE IF EXISTS file_recrods;
CREATE TABLE IF NOT EXISTS file_records
(
	time timestamp with time zone NOT NULL DEFAULT now(),
	username varchar(1024) NOT NULL,
	chunk_hash varchar(1024) NOT NULL,
	chunk_guid UUID NOT NULL,
	rootdir_guid UUID NOT NULL,
	file_guid UUID NOT NULL,
	revision_guid UUID NOT NULL,
	chunk_path varchar(1024) NOT NULL,
	"offset" integer NOT NULL DEFAULT 0,
	origin integer NOT NULL DEFAULT 0
);

DROP TABLE IF EXISTS file_keys;
CREATE TABLE IF NOT EXISTS file_keys
(
	time timestamp with time zone NOT NULL DEFAULT now(),
	username varchar(1024) NOT NULL,
	rootdir_guid UUID NOT NULL,
	file_guid UUID NOT NULL,
	revision_guid UUID DEFAULT NULL,
	directory_guid UUID NOT NULL,
	parent_revision_guid UUID DEFAULT NULL,
	enc_filename varchar(1024) NOT NULL,
	deviceid bigint NOT NULL,
	public_key varchar(4096) NOT NULL
);

DROP TABLE IF EXISTS directory_log CASCADE;
CREATE TABLE IF NOT EXISTS directory_log
(
	time timestamp with time zone NOT NULL DEFAULT now(),
	username varchar(1024) NOT NULL,
	rootdir_guid UUID NOT NULL,
	directory_guid UUID NOT NULL,
	path varchar(4096) DEFAULT NULL,
	deviceid bigint NOT NULL
);

/* таблица directory_tree должна заполняться автоматически
   	 по триггеру в таблице directory_log
   	 содержит текущий список каталогов
   	 */
DROP TABLE IF EXISTS directory_tree;
CREATE TABLE IF NOT EXISTS directory_tree (LIKE directory_log);


CREATE UNIQUE INDEX file_keys_urfr_idx
ON file_keys
(
	lower(username),
	rootdir_guid,
	file_guid,
	revision_guid
);

CREATE UNIQUE INDEX file_records_urfcr_idx
ON file_records
(
	lower(username),
	rootdir_guid,
	file_guid,
	revision_guid,
	chunk_guid
);

CREATE OR REPLACE FUNCTION fepserver_installed()
	RETURNS text AS $$
DECLARE
	_retval text;
BEGIN
	SELECT INTO _retval version();
	RETURN _retval;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION directory_action()
	RETURNS TRIGGER AS $$
BEGIN
	IF NEW.path IS NULL THEN
		DELETE FROM directory_tree
		WHERE
			username = NEW.username AND
			rootdir_guid = NEW.rootdir_guid AND
			directory_guid = NEW.directory_guid;
		/* TODO: добавить событий удаления поддиректорий и файлов */
	ELSE
		IF substring(NEW.path from 1 for 1) != '/' THEN
			NEW.path = concat('/', NEW.path);
		END IF;
		INSERT INTO directory_tree SELECT NEW.*;
	END IF;
	RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tr_directory_action ON directory_log;
CREATE TRIGGER tr_directory_action BEFORE INSERT ON directory_log FOR EACH ROW EXECUTE PROCEDURE directory_action();



