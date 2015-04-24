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

-- удаление таблиц не должно вызывать NOTICE с нерзрешёнными CONSTRAINT
DROP TABLE IF EXISTS file_chunk CASCADE;
DROP TABLE IF EXISTS file_revision CASCADE;
DROP TABLE IF EXISTS options CASCADE;
DROP TABLE IF EXISTS file CASCADE;
DROP TABLE IF EXISTS directory CASCADE;
DROP TABLE IF EXISTS directory_log CASCADE;
DROP TABLE IF EXISTS event CASCADE;
DROP TABLE IF EXISTS rootdir CASCADE;
DROP TABLE IF EXISTS rootdir_log CASCADE;
DROP TABLE IF EXISTS "user" CASCADE;

DROP SEQUENCE IF EXISTS directory_seq CASCADE;
DROP SEQUENCE IF EXISTS directory_log_seq CASCADE;
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
	time timestamp with time zone NOT NULL DEFAULT now(),
	user_id bigint NOT NULL REFERENCES "user"(id),
	
	-- для удобства вставки в лог и получение чекпоинта
	checkpoint bigint NOT NULL,
	rootdir_id bigint NOT NULL,

	rootdir_guid UUID NOT NULL DEFAULT gen_random_uuid(),
	title varchar(1024) DEFAULT NULL
);

CREATE SEQUENCE rootdir_seq;
-- текущее состояние рутдир
CREATE TABLE IF NOT EXISTS rootdir
(
	-- id должен генерируется в directory_log_action
	id bigint NOT NULL PRIMARY KEY,
	user_id bigint NOT NULL REFERENCES "user"(id),

	log_id bigint NOT NULL REFERENCES rootdir_log(id),

	rootdir_guid UUID NOT NULL,
	title varchar(1024) NOT NULL,
	
	UNIQUE (user_id, rootdir_guid)
);

CREATE TABLE IF NOT EXISTS options
(
	"key" varchar(16) NOT NULL CHECK(char_length("key") > 0),
	value_c varchar(64) DEFAULT NULL,
	value_i integer DEFAULT NULL,
	value_u UUID DEFAULT NULL
);

CREATE TYPE event_type AS ENUM ('directory', 'file', 'rootdir');

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
CREATE SEQUENCE directory_log_seq;
-- если path IS NULL, то это удаление, иначе создание/переменование
-- INSERT INTO directory_log(rootdir_id, directory_id, path) ...
-- INSERT INTO directory_log(rootdir_id, directory_guid, path) ...
CREATE TABLE IF NOT EXISTS directory_log
(
	id bigint DEFAULT nextval('directory_log_seq') PRIMARY KEY,
	-- время создания директории
	time timestamp with time zone NOT NULL DEFAULT now(),
	rootdir_id bigint NOT NULL REFERENCES rootdir(id),
	
	checkpoint bigint DEFAULT NULL,
	directory_id bigint DEFAULT NULL,

	directory_guid UUID NOT NULL,
	path varchar(4096) DEFAULT NULL
);

CREATE SEQUENCE directory_seq;
/* таблица directory_tree должна заполняться автоматически
   	 по триггеру в таблице directory_log
   	 содержит текущий список каталогов
   	 */
CREATE TABLE IF NOT EXISTS directory
(
	id bigint PRIMARY KEY,
	
	rootdir_id bigint NOT NULL REFERENCES rootdir(id),
	-- информацию по времени создания и чекпоинт можно получить из directory_log
	log_id bigint NOT NULL REFERENCES directory_log(id),

	directory_guid UUID NOT NULL,
	path varchar(4096) DEFAULT NULL,

	UNIQUE(rootdir_id, directory_guid),
	UNIQUE(rootdir_id, path)
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
	dir_id bigint NOT NULL REFERENCES directory(id)
);

CREATE SEQUENCE file_revision_seq;
CREATE TABLE IF NOT EXISTS file_revision
(
	id bigint DEFAULT nextval('file_revision_seq') PRIMARY KEY,
	file_id bigint NOT NULL REFERENCES file(id),

	revision UUID NOT NULL,
	parent_id bigint DEFAULT NULL REFERENCES file_revision(id)
);

CREATE SEQUENCE file_chunk_seq;
CREATE TABLE IF NOT EXISTS file_chunk
(
	id bigint DEFAULT nextval('file_chunk_seq') PRIMARY KEY,
	revision_id bigint NOT NULL REFERENCES file_revision(id),
	
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

-- при создании пользователя заполняет таблицу базовыми значениями
CREATE OR REPLACE FUNCTION user_action()
	RETURNS trigger AS $$
DECLARE
	_row record;
BEGIN
	-- подсовывание стандартных рутдир пользователю
	FOR _row IN SELECT value_c, value_u FROM options WHERE "key" LIKE '%\_rootdir' LOOP
		INSERT INTO rootdir_log(user_id, rootdir_guid, title)
		VALUES(new.id, _row.value_u, _row.value_c);
	END LOOP;
	return new;
END $$ LANGUAGE plpgsql;

-- инициализация рутдир, заполнение стандартными директориями
CREATE OR REPLACE FUNCTION rootdir_action()
	RETURNS trigger AS $$
DECLARE
	_row record;
BEGIN
	-- впихнуть стандартные директории в рутдиру
	FOR _row IN SELECT value_c, value_u FROM options WHERE "key" LIKE '%\_dir' LOOP
		INSERT INTO directory_log(rootdir_id, directory_guid, path)
		VALUES(new.id, _row.value_u, _row.value_c);
	END LOOP;
	return new;
END $$ LANGUAGE plpgsql;

-- подготовка к заплонения rootdir, заполнение пустых полей и отметка в event
CREATE OR REPLACE FUNCTION rootdir_log_action()
	RETURNS trigger AS $$
DECLARE
	_row record;
BEGIN
	-- TODO: удаление рутдир не готово (1)
	IF new.title IS NULL THEN
		IF new.rootdir_guid IS NULL AND new.rootdir_id IS NULL THEN
			RAISE EXCEPTION 'no rootdir_guid and rootdir_id for destroy';
			return new;
		END IF;
		RAISE EXCEPTION 'rootdir destroy not implement';
		return new;
	END IF;

	SELECT NULL INTO _row;

	-- проверяем наличие директории по id или по guid
	CASE
	WHEN new.rootdir_id IS NOT NULL THEN
		-- по идее, сдесь user_id не нужен, но ну его нафиг, перестрахуемся
		SELECT * INTO _row FROM rootdir
		WHERE user_id = new.user_id AND id = new.rootdir_id;
		-- вроде бы отсутвующая директория по rootdir_id и пустой
		-- rootdir_guid означают что произошла какая-то ошибка
	WHEN new.rootdir_guid IS NOT NULL THEN
		SELECT * INTO _row FROM rootdir
		WHERE user_id = new.user_id AND rootdir_guid = new.rootdir_guid;
	END CASE;

	IF _row IS NOT NULL THEN
		new.rootdir_id = _row.id;
		new.rootdir_guid = _row.rootdir_guid;
	ELSE 
		-- форсируем получение rootdir_id
		new.rootdir_id = nextval('rootdir_seq');
	END IF;

	-- отмечаемся в логе событий
	with _row AS (
		INSERT INTO event (rootdir_guid, "type", target_id)
		VALUES (new.rootdir_guid, 'rootdir', new.id)
		RETURNING *
	) SELECT checkpoint INTO new.checkpoint FROM _row;

	-- сохраняем запись, переходим к триггеру AFTER
	return new;
END $$ LANGUAGE plpgsql;

-- заполнение rootdir
CREATE OR REPLACE FUNCTION rootdir_log_action_after()
	RETURNS trigger AS $$
DECLARE
	_row record;
BEGIN
	-- TODO: удаление рутдир не готово (2)
	IF new.title IS NULL THEN
		RAISE EXCEPTION 'rootdir destroy not implement';
		return new;
	END IF;

	-- простой апсерт

	WITH _row AS (
		UPDATE rootdir SET
			log_id = new.id,
			title = new.title
		WHERE
			user_id = new.user_id
			AND ((new.rootdir_id IS NOT NULL AND id = new.rootdir_id)
				OR (new.rootdir_id IS NULL AND TRUE))
			AND ((new.rootdir_guid IS NOT NULL
				AND rootdir_guid = new.rootdir_guid)
				OR (new.rootdir_guid IS NULL AND TRUE))
		RETURNING *
	)
	INSERT INTO rootdir (id, user_id, log_id, rootdir_guid, title)
		SELECT new.rootdir_id, new.user_id, new.id, new.rootdir_guid, new.title
		WHERE NOT EXISTS (SELECT * FROM _row);

	return new;
END $$ LANGUAGE plpgsql;

-- по принципу rootdir_log_action/rootdir_log_action_after
CREATE OR REPLACE FUNCTION directory_log_action()
	RETURNS TRIGGER AS $$
DECLARE
	_row record;
BEGIN
	
	IF new.path IS NULL THEN
		raise exception 'directory deletion not implemented';
		return new;
	END IF;

	-- причёсывание пути, если вдруг прислали ошмёток (как?)
	IF substring(NEW.path from 1 for 1) != '/' THEN
		NEW.path = concat('/', NEW.path);
	END IF;

	SELECT NULL INTO _row;

	-- проверка наличия директории
	CASE
	WHEN new.directory_id IS NOT NULL THEN
		SELECT * INTO _row FROM directory
		WHERE rootdir_id = new.rootdir_id AND id = new.directory_id;
	WHEN new.directory_guid IS NOT NULL THEN
		SELECT * INTO _row FROM directory
		WHERE rootdir_id = new.rootdir_id AND directory_guid = new.directory_guid;
	END CASE;

	IF _row IS NOT NULL THEN
		new.directory_id = _row.id;
		new.directory_guid = _row.directory_guid;
	ELSE
		new.directory_id = nextval('directory_seq');
	END IF;

	-- получение checkpoint в логе
	WITH _row AS (
		INSERT INTO event (rootdir_guid, "type", target_id)
		VALUES ((SELECT rootdir_guid FROM rootdir WHERE id = new.rootdir_id),
			'directory', new.id)
		RETURNING *
	) SELECT checkpoint FROM _row INTO new.checkpoint;

	return new;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION directory_log_action_after()
	RETURNS trigger AS $$
DECLARE
	_row record;
BEGIN
	IF new.path IS NULL THEN
		raise exception 'directory deletion not implemented';
		return new;
	END IF;

	WITH _row AS (
		UPDATE directory SET
			log_id = new.id,
			path = new.path
		WHERE rootdir_id = new.rootdir_id
			AND ((new.directory_id IS NOT NULL AND id = new.directory_id)
				OR (new.directory_id IS NULL AND TRUE))
			AND ((new.directory_guid IS NOT NULL AND directory_guid = new.directory_guid)
				OR (new.directory_guid IS NULL AND TRUE))
		RETURNING *
	)
	INSERT INTO directory (id, rootdir_id, log_id, directory_guid, path)
		SELECT new.directory_id, new.rootdir_id, new.id, new.directory_guid, new.path
		WHERE NOT EXISTS (SELECT * FROM _row);

	return new;
END $$ LANGUAGE plpgsql;

-- вешанье триггеров, инжекция базовых значений

CREATE TRIGGER tr_user_action AFTER INSERT ON "user"
	FOR EACH ROW EXECUTE PROCEDURE user_action();

-- rootdir_log
CREATE TRIGGER tr_rootdir_log_action BEFORE INSERT ON rootdir_log
	FOR EACH ROW EXECUTE PROCEDURE rootdir_log_action();

CREATE TRIGGER tr_rootdir_log_action_after AFTER INSERT ON rootdir_log
	FOR EACH ROW EXECUTE PROCEDURE rootdir_log_action_after();

CREATE TRIGGER tr_rootdir_action AFTER INSERT ON rootdir
	FOR EACH ROW EXECUTE PROCEDURE rootdir_action();

-- directory_log
CREATE TRIGGER tr_directory_log_action BEFORE INSERT ON directory_log
	FOR EACH ROW EXECUTE PROCEDURE directory_log_action();

CREATE TRIGGER tr_directory_log_action_after AFTER INSERT ON directory_log
	FOR EACH ROW EXECUTE PROCEDURE directory_log_action_after();

INSERT INTO options ("key", value_c, value_u)
	VALUES ('trash_dir', '.Trash', '10000002-3004-5006-7008-900000000000');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('incomplete_dir', '.Incomplete',
		'20000002-3004-5006-7008-900000000000');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('1_rootdir', 'First', 
		'00000001-2003-5406-7008-900000000000');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('2_rootdir', 'First', 
		'11000001-2003-5406-7008-900000000000');


