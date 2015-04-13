/*	vim: synta=pgsql
*/

CREATE OR REPLACE FUNCTION directory_action()
RETURNS TRIGGER AS $$
BEGIN
	RAISE NOTICE 'path %', NEW.path;
	IF NEW.path IS NULL THEN
		RAISE NOTICE 'SELECT FROM directory_tree WHERE username = % AND rootdir_guid = % AND directory_guid = %;',
			NEW.username, NEW.rootdir_guid, NEW.directory_guid;
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



