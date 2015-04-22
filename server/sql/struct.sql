/*	vim: syntax=pgsql
	текущая версия задаётся в fepserver_installed()
*/

CREATE OR REPLACE FUNCTION fepserver_installed()
	RETURNS text AS $$
DECLARE
	_struct_version_value text;
	_exc_str text;
BEGIN
	/* версия структуры */
	SELECT INTO _struct_version_value '3';

	/* проверка pgcrypto, на всякий случай */
	BEGIN
		PERFORM gen_random_uuid();
	EXCEPTION WHEN undefined_function THEN
		GET STACKED DIAGNOSTICS _exc_str = MESSAGE_TEXT;
		RAISE EXCEPTION
			'check pgcrypto: %', _exc_str
			USING HINT = 'try to `CREATE EXCEPTION pgcrypto` in this database';
	END;


	RETURN _struct_version_value;
END $$ LANGUAGE plpgsql;

/* обновление табличного пространства */

DROP TRIGGER IF EXISTS tr_directory_action ON directory_log;

DROP TABLE IF EXISTS rootdir_log CASCADE;
DROP TABLE IF EXISTS file_chunk CASCADE;
DROP TABLE IF EXISTS file_revision CASCADE;
DROP TABLE IF EXISTS options CASCADE;
DROP TABLE IF EXISTS file CASCADE;
DROP TABLE IF EXISTS directory_tree CASCADE;
DROP TABLE IF EXISTS directory_log CASCADE;
DROP TABLE IF EXISTS event CASCADE;
DROP TABLE IF EXISTS rootdir CASCADE;
DROP TABLE IF EXISTS "user" CASCADE;

DROP SEQUENCE IF EXISTS directory_tree_seq CASCADE;
DROP SEQUENCE IF EXISTS file_revision_seq CASCADE;
DROP SEQUENCE IF EXISTS file_chunk_seq CASCADE;
DROP SEQUENCE IF EXISTS file_seq CASCADE;
DROP SEQUENCE IF EXISTS user_seq CASCADE;
DROP SEQUENCE IF EXISTS event_seq CASCADE;
DROP SEQUENCE IF EXISTS rootdir_log_seq CASCADE;
DROP SEQUENCE IF EXISTS rootdir_seq CASCADE;

DROP TYPE IF EXISTS event_type CASCADE;

CREATE SEQUENCE user_seq;
CREATE TABLE IF NOT EXISTS "user"
(
	id bigint NOT NULL DEFAULT nextval('user_seq') PRIMARY KEY,
	username varchar(1024) NOT NULL CHECK(char_length(username) > 0)
);

CREATE SEQUENCE rootdir_log_seq;
-- лог создания/удаления рутдир
CREATE TABLE IF NOT EXISTS rootdir_log
(
	id bigint NOT NULL DEFAULT nextval('rootdir_log_seq') PRIMARY KEY,
	rootdir_id bigint NOT NULL,
	user_id bigint REFERENCES "user"(id),
	
	-- для удобства вставки в лог и получение чекпоинта
	checkpoint bigint NOT NULL,

	rootdir_guid UUID NOT NULL DEFAULT gen_random_uuid(),
	-- если NULL, то директория удаляется
	title varchar(1024) DEFAULT NULL
);

CREATE SEQUENCE rootdir_seq;
-- текущее состояние рутдир
CREATE TABLE IF NOT EXISTS rootdir
(
	id bigint NOT NULL DEFAULT nextval('rootdir_seq') PRIMARY KEY,
	user_id bigint REFERENCES "user"(id),
	rootdir_guid UUID NOT NULL UNIQUE,
	title varchar(1024) NOT NULL
);

CREATE TABLE IF NOT EXISTS options
(
	"key" varchar(16) NOT NULL CHECK(char_length("key") > 0),
	value_c varchar(64) DEFAULT NULL,
	value_i integer DEFAULT NULL,
	value_u UUID DEFAULT NULL
);

CREATE TYPE event_type AS ENUM ('dir', 'file', 'rootdir');

CREATE SEQUENCE event_seq;
CREATE TABLE IF NOT EXISTS event
(
	id bigint NOT NULL DEFAULT nextval('event_seq') PRIMARY KEY,
	checkpoint bigint NOT NULL DEFAULT trunc(extract(epoch from now())),
	-- требуется для фильтрации событий
	-- поле не ссылается на rootdir(id) потому что лог не особо полезен
	-- и может в любой момент быть затёрт
	-- (checkpoint так же хранится в состояниях каталогов/файлов и может быть получен оттуда)
	rootdir_guid UUID NOT NULL,
	"type" event_type NOT NULL,
	-- указатель на id в таблице, которая ицнициировала событие
	target_id bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS directory_log
(
	time timestamp with time zone NOT NULL DEFAULT now(),
	event_id bigint NOT NULL REFERENCES event(id),
	user_id bigint NOT NULL REFERENCES "user"(id),
	rootdir_guid UUID NOT NULL,
	directory_guid UUID NOT NULL,
	path varchar(4096) DEFAULT NULL,
	deviceid bigint NOT NULL
);

CREATE SEQUENCE directory_tree_seq;
/* таблица directory_tree должна заполняться автоматически
   	 по триггеру в таблице directory_log
   	 содержит текущий список каталогов
   	 */
CREATE TABLE IF NOT EXISTS directory_tree
(
	id bigint DEFAULT nextval('directory_tree_seq') PRIMARY KEY,
	time timestamp with time zone NOT NULL DEFAULT now(),
	checkpoint bigint NOT NULL DEFAULT trunc(extract(epoch from now())),
	user_id bigint NOT NULL REFERENCES "user"(id),
	rootdir_guid UUID NOT NULL,
	directory_guid UUID NOT NULL,
	path varchar(4096) DEFAULT NULL,
	deviceid bigint NOT NULL,
	UNIQUE(user_id, rootdir_guid, directory_guid)
);

CREATE SEQUENCE file_seq;
CREATE TABLE IF NOT EXISTS file
(
	/* постоянные поля */
	user_id bigint NOT NULL REFERENCES "user"(id),
	id bigint DEFAULT nextval('file_seq') PRIMARY KEY,
	file UUID NOT NULL,
	rootdir UUID NOT NULL,
	filename varchar(4096) NOT NULL DEFAULT '',
	pubkey varchar(4096) NOT NULL DEFAULT '',
	/* обновляемые поля */
	dir_id bigint REFERENCES directory_tree(id)
);

CREATE SEQUENCE file_revision_seq;
CREATE TABLE IF NOT EXISTS file_revision
(
	id bigint DEFAULT nextval('file_revision_seq') PRIMARY KEY,
	file_id bigint REFERENCES file(id),

	revision UUID NOT NULL,
	parent_id bigint DEFAULT NULL REFERENCES file_revision(id)
);

CREATE SEQUENCE file_chunk_seq;
CREATE TABLE IF NOT EXISTS file_chunk
(
	id bigint DEFAULT nextval('file_chunk_seq') PRIMARY KEY,
	revision_id bigint REFERENCES file_revision(id),
	
	chunk UUID NOT NULL,
	
	/* параметры чанка */
	size integer NOT NULL,
	"offset" integer NOT NULL,
	/* размер оригинальных данных в зашифрованном чанке
	 	не должно сдесь быть, но присутсвует из-за того,
		что кто-то поленился добавить фиксированный заголовок в начало
		кадождого чанка
	 */
	data_size integer NOT NULL
);

/* триггеры и процедурки */

CREATE OR REPLACE FUNCTION directory_action()
	RETURNS TRIGGER AS $$
DECLARE
	rows_affected integer default 0;
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

		UPDATE directory_tree
		SET
			path = NEW.path, time = NEW.time,
			checkpoint = NEW.checkpoint, deviceid = NEW.deviceid
		WHERE username = NEW.username AND
			rootdir_guid = NEW.rootdir_guid AND
			directory_guid = NEW.directory_guid;
		GET DIAGNOSTICS rows_affected = ROW_COUNT;
		/* TODO: добавить события на переименование подкаталогов */
		if rows_affected < 1 then
			INSERT INTO directory_tree SELECT NEW.*;
		end if;
	END IF;
	RETURN NEW;
END $$ LANGUAGE plpgsql;

/*
	при создании пользователя заполняет таблицу базовыми значениями
*/
CREATE OR REPLACE FUNCTION user_action()
	RETURNS trigger AS $$
DECLARE
BEGIN
	RAISE INFO 'try `SELECT user_init(%)` to initialize user', new.id;
	return new;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION user_init(_id bigint)
	RETURNS void AS $$
DECLARE
BEGIN
	/* в первую очередь, нужно создать корневую директорию */
	INSERT INTO rootdir_log (user_id, title) VALUES (_id, 'First');
END $$ LANGUAGE plpgsql;

-- обработчик добавления в rootdir_log
CREATE OR REPLACE FUNCTION rootdir_log_action()
	RETURNS trigger AS $$
DECLARE
	_row record;
	_null record;
	_checkpoint bigint;
BEGIN
	if new.title IS NOT NULL then
		-- можно проверить на NULL new.rootdir_id и new.rootdir_guid
		-- но пока проще сделать попытку апдейта
		WITH _row AS (
			UPDATE rootdir SET title = new.title
			WHERE
				user_id = new.user_id
				AND (new.rootdir_id IS NULL AND rootdir_guid = new.rootdir_guid
					OR id = new.rootdir_id)
			RETURNING *
		) SELECT * FROM _row INTO _null;
		-- а потом впихнуть запись, если не апдейтнулось
		if _null IS NULL then
			WITH _row AS (
				INSERT INTO rootdir (user_id, rootdir_guid, title)
				VALUES (new.user_id, new.rootdir_guid, new.title)
				RETURNING *
			) SELECT * FROM _row INTO _null;
		end if;
	else -- удаление рутдиры
		if new.rootdir_guid IS NULL AND new.rootdir_id IS NULL then
			RAISE EXCEPTION 'rootidr destroy: no id or guid (user: %)',
				(SELECT username FROM "user" WHERE id = new.user_id);
			return new;
		end if;
		/*
		with _row AS (
			DELETE FROM rootdir
			WHERE
				user_id = new.user_id
				AND (new.rootdir_id IS NULL AND rootdir_guid = new.rootdir_guid
					OR id = new.rootdir_id)
			RETURNING *
		) SELECT rootdir_guid INTO _row_id FROM _row;
		*/
		RAISE EXCEPTION 'rootdir destroy not implement (user: %, rootdir: %)',
			(SELECT username FROM "user" WHERE id = new.user_id), new.rootdir_guid;
	end if;
	if _null IS NULL then
		RAISE EXCEPTION 'rootdir(% "%") update failed', new.rootdir_guid, new.title;
		return new;
	end if;

	new.rootdir_id = _null.id;
	-- добавление записи в события и получение чекпоинта
	with _row AS (
		INSERT INTO event (rootdir_guid, "type", target_id)
		VALUES (_null.rootdir_guid, 'rootdir', new.id)
		RETURNING *
		) SELECT checkpoint INTO _checkpoint FROM _row;
	new.checkpoint = _checkpoint;
	return new;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION chunk_insert(
	_username varchar,
	_rootdir UUID, _file UUID, _revision UUID, _chunk UUID,
	_size integer, _data_size integer, _offset integer,
	_hash varchar)
RETURNS boolean AS $$
DECLARE
	_id RECORD;
BEGIN
	SELECT
		file.id AS file_id,
		file_revision.id AS revision_id,
		directory_tree.id AS directory_id
	INTO _id
	FROM file, file_revision, directory_tree
	WHERE
		file.rootdir = _rootdir AND
		file.file = _file AND
		file_revision.file_id = file.id;
	/* если id нет, то нужно впихнуть соотвествующие записи */
	/*
	if _id.file_id IS NULL then
		INSERT INTO file (file, rootdir, dir_id, username)
		VALUES ();
	end if
	*/
END $$ LANGUAGE plpgsql;

/* вешанье триггеров, инжекция базовых значений */
CREATE TRIGGER tr_directory_action BEFORE INSERT ON directory_log
	FOR EACH ROW EXECUTE PROCEDURE directory_action();
CREATE TRIGGER tr_user_action AFTER INSERT ON "user"
	FOR EACH ROW EXECUTE PROCEDURE user_action();
CREATE TRIGGER tr_rootdir_log_action BEFORE INSERT ON rootdir_log
	FOR EACH ROW EXECUTE PROCEDURE rootdir_log_action();

INSERT INTO options ("key", value_c, value_u)
	VALUES ('trash_dir', '.Trash', '10000002-3004-5006-7008-900000000000');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('incomplete_dir', '.Incomplete',
		'20000002-3004-5006-7008-900000000000');

