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
DROP TABLE IF EXISTS file_log CASCADE;
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
DROP SEQUENCE IF EXISTS file_log_seq CASCADE;
DROP SEQUENCE IF EXISTS event_checkpoint_seq CASCADE;

DROP TYPE IF EXISTS _drop_ CASCADE;
DROP TYPE IF EXISTS event_type CASCADE;

-- костыль для гроханья всех хранимых процедур
CREATE TYPE _drop_ AS ENUM ('drop');

CREATE SEQUENCE user_seq;
CREATE TABLE IF NOT EXISTS "user"
(
	id bigint NOT NULL DEFAULT nextval('user_seq') PRIMARY KEY,
	username varchar(1024) NOT NULL CHECK(char_length(username) > 0),
	secret varchar(96) NOT NULL,
	UNIQUE(username)
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

	rootdir UUID NOT NULL DEFAULT gen_random_uuid(),
	title varchar(1024) DEFAULT NULL,
	UNIQUE(checkpoint)
);

CREATE SEQUENCE rootdir_seq;
-- текущее состояние рутдир
CREATE TABLE IF NOT EXISTS rootdir
(
	-- id должен генерируется в directory_log_action
	id bigint NOT NULL PRIMARY KEY,
	user_id bigint NOT NULL REFERENCES "user"(id),

	log_id bigint NOT NULL REFERENCES rootdir_log(id),

	rootdir UUID NOT NULL,
	title varchar(1024) NOT NULL,
	
	UNIQUE (user_id, rootdir)
);

CREATE TABLE IF NOT EXISTS options
(
	"key" varchar(16) NOT NULL CHECK(char_length("key") > 0),
	value_c varchar(64) DEFAULT NULL,
	value_i integer DEFAULT NULL,
	value_u UUID DEFAULT NULL
);

-- directory: переименование/удаление директории
-- file: создание/удаление/ревизия файла
-- rootdir: создание/удаление корневой директории
CREATE TYPE event_type AS ENUM ('directory', 'file', 'rootdir');

CREATE SEQUENCE event_checkpoint_seq;
CREATE SEQUENCE event_seq;
CREATE TABLE IF NOT EXISTS event
(
	id bigint NOT NULL DEFAULT nextval('event_seq') PRIMARY KEY,
	user_id bigint NOT NULL REFERENCES "user"(id),
	checkpoint bigint NOT NULL DEFAULT nextval('event_checkpoint_seq'),
	-- требуется для фильтрации событий
	-- поле не ссылается на rootdir(id) потому что лог не особо полезен
	-- и может в любой момент быть затёрт
	-- (checkpoint так же хранится в состояниях каталогов/файлов и может быть получен оттуда)
	rootdir UUID NOT NULL,
	"type" event_type NOT NULL,
	-- указатель на id в таблице, которая ицнициировала событие
	target_id bigint NOT NULL,
	-- идентификатор устройства
	device_id integer DEFAULT NULL,
	UNIQUE(checkpoint)
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

	directory UUID NOT NULL,
	path varchar(4096) DEFAULT NULL,
	UNIQUE(checkpoint)
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

	directory UUID NOT NULL,
	path varchar(4096) DEFAULT NULL,

	UNIQUE(rootdir_id, directory),
	UNIQUE(rootdir_id, path)
);

-- у самого файла нет чекпоинта, чекпоинт есть у имени/пути файла и ревизии
CREATE SEQUENCE file_seq;
CREATE TABLE IF NOT EXISTS file
(
	id bigint DEFAULT nextval('file_seq') PRIMARY KEY,

	-- постоянные поля
	file UUID NOT NULL,
	rootdir_id bigint NOT NULL REFERENCES rootdir(id),
	pubkey varchar(4096) NOT NULL DEFAULT '',

	-- обновляемые поля
	directory_id bigint NOT NULL REFERENCES directory(id),
	filename varchar(4096) NOT NULL DEFAULT '',

	UNIQUE(rootdir_id, file),
	UNIQUE(directory_id, filename)
);

-- доступ к чекпоинту ревизии через file_log
CREATE SEQUENCE file_revision_seq;
CREATE TABLE IF NOT EXISTS file_revision
(
	id bigint DEFAULT nextval('file_revision_seq') PRIMARY KEY,
	file_id bigint NOT NULL REFERENCES file(id),

	revision UUID NOT NULL,
	parent_id bigint DEFAULT NULL REFERENCES file_revision(id),

	-- количество чанков в ревизии
	chunks integer NOT NULL DEFAULT 0,
	UNIQUE(file_id, revision)
);

CREATE SEQUENCE file_log_seq;
CREATE TABLE IF NOT EXISTS file_log
(
	id bigint DEFAULT nextval('file_log_seq') PRIMARY KEY,
	time timestamp with time zone NOT NULL DEFAULT now(),
	file_id bigint NOT NULL REFERENCES file(id),
	revision_id bigint NOT NULL REFERENCES file_revision(id),
	-- file_guid здесь не нужен
	checkpoint bigint DEFAULT NULL,

	filename varchar(4096) NOT NULL DEFAULT '',
	pubkey varchar (4096) NOT NULL DEFAULT '',
	directory_id bigint NOT NULL,
	UNIQUE(checkpoint)
);

CREATE SEQUENCE file_chunk_seq;
CREATE TABLE IF NOT EXISTS file_chunk
(
	id bigint DEFAULT nextval('file_chunk_seq') PRIMARY KEY,
	revision_id bigint NOT NULL REFERENCES file_revision(id),
	-- глобальный id чанка собирается из (rootdir_guid, file_guid, chunk_guid)
	file_id bigint NOT NULL REFERENCES file(id),

	chunk UUID NOT NULL,
	
	/* параметры чанка */
	size integer NOT NULL,
	"offset" integer NOT NULL,
	hash character varying(256) NOT NULL,
	-- путь к файлу
	address text NOT NULL
);

/* триггеры и процедурки */

-- автозаполнение полей
CREATE OR REPLACE FUNCTION event_action()
	RETURNS trigger AS $$
BEGIN
	IF new.device_id IS NULL THEN
		BEGIN
			-- проверочка нужна что бы не произошло лишнего смешения
			SELECT INTO new.device_id device_id
			FROM _life_, "user", options
			WHERE
				"user".id = new.user_id AND
				_life_.user_id = new.user_id AND
				_life_.username = "user".username AND
				options."key" = 'life_mark' AND
				_life_.mark = options.value_u;
		EXCEPTION
			WHEN undefined_table THEN -- nothing
		END;
	END IF;
	return new;
END $$ LANGUAGE plpgsql;

-- при создании пользователя заполняет таблицу базовыми значениями
CREATE OR REPLACE FUNCTION user_action()
	RETURNS trigger AS $$
DECLARE
	_row record;
BEGIN
	-- подсовывание стандартных рутдир пользователю
	FOR _row IN SELECT value_c, value_u FROM options WHERE "key" LIKE '%\_rootdir' LOOP
		INSERT INTO rootdir_log(user_id, rootdir, title)
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
		INSERT INTO directory_log(rootdir_id, directory, path)
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
		IF new.rootdir IS NULL AND new.rootdir_id IS NULL THEN
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
	WHEN new.rootdir IS NOT NULL THEN
		SELECT * INTO _row FROM rootdir
		WHERE user_id = new.user_id AND rootdir = new.rootdir;
	END CASE;

	IF _row IS NOT NULL THEN
		new.rootdir_id = _row.id;
		new.rootdir = _row.rootdir;
	ELSE 
		-- форсируем получение rootdir_id
		new.rootdir_id = nextval('rootdir_seq');
	END IF;

	-- отмечаемся в логе событий
	with _row AS (
		INSERT INTO event (user_id, rootdir, "type", target_id)
		VALUES (new.user_id, new.rootdir, 'rootdir', new.id)
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
			AND ((new.rootdir IS NOT NULL
				AND rootdir = new.rootdir)
				OR (new.rootdir IS NULL AND TRUE))
		RETURNING *
	)
	INSERT INTO rootdir (id, user_id, log_id, rootdir, title)
		SELECT new.rootdir_id, new.user_id, new.id, new.rootdir, new.title
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
	WHEN new.directory IS NOT NULL THEN
		SELECT * INTO _row FROM directory
		WHERE rootdir_id = new.rootdir_id AND directory = new.directory;
	END CASE;

	IF _row IS NOT NULL THEN
		new.directory_id = _row.id;
		new.directory = _row.directory;
	ELSE
		new.directory_id = nextval('directory_seq');
	END IF;

	-- получение checkpoint в логе
	WITH _row AS (
		INSERT INTO event (user_id, rootdir, "type", target_id)
			SELECT user_id AS user_id,
				rootdir AS rootdir,
				'directory' AS "type",
				new.id AS target_id
			FROM rootdir WHERE id = new.rootdir_id
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
			AND ((new.directory IS NOT NULL AND directory = new.directory)
				OR (new.directory IS NULL AND TRUE))
		RETURNING *
	)
	INSERT INTO directory (id, rootdir_id, log_id, directory, path)
		SELECT new.directory_id, new.rootdir_id, new.id, new.directory, new.path
		WHERE NOT EXISTS (SELECT * FROM _row);

	return new;
END $$ LANGUAGE plpgsql;

-- обновляет счётчик чанков в file_revision
CREATE OR REPLACE FUNCTION file_chunk_action_after()
	RETURNS trigger AS $$
BEGIN
	UPDATE file_revision SET chunks = (chunks + 1)
	WHERE file_revision.id = new.revision_id;
	return new;
END $$ LANGUAGE plpgsql;

/* упрощалки жизни */

-- облегчающий жизнь костыль, должен вызываться перед началом всех
-- "простых" операций, сохраняет значение текущего имени пользователя 
-- и id устройства
CREATE OR REPLACE FUNCTION begin_life(_username "user".username%TYPE,
	_device_id integer, _drop_ _drop_ DEFAULT 'drop')
	RETURNS void AS $$
DECLARE
	_x integer;
	_n record;
BEGIN
	-- создаём временную таблицу
	-- использовать .. ON COMMIT DROP нельзя
	-- потому что COMMIT произойдёт в конце этой процедуры
	-- FIXME: эффект кеша
	BEGIN
		SELECT INTO _n * FROM _life_;
		DROP TABLE _life_;
	EXCEPTION
		WHEN undefined_table THEN -- nothing
	END;
	CREATE TEMP TABLE IF NOT EXISTS _life_
	(
		mark UUID,
		username character varying(1024),
		user_id bigint,
		device_id integer
	);
	-- и чистим её, что бы не было случайных наложений
	TRUNCATE TABLE _life_;

	INSERT INTO _life_
		SELECT options.value_u, _username, "user".id, _device_id FROM "user", options
		WHERE "user".username = _username AND options."key" = 'life_mark';

	GET DIAGNOSTICS _x = ROW_COUNT;
	IF _x = 0 THEN
		DROP TABLE _life_;
		RAISE EXCEPTION 'no user with name `%` in database', _username;
	END IF;
	
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_file(
	_rootdir_guid UUID, _file_guid UUID, _name character varying(1024),
	_dir_guid UUID, _pubkey character varying(4096),
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS text AS $$
BEGIN
	-- условия:
	-- 1. если файл уже имеет ключ не нулевой длины, новый ключ
	-- 2. любое поле из (_name, _dir_guid, pubkey) может быть NULL, остальные не могут

	-- TODO:
	RAISE EXCEPTION 'not implemented';
	return NULL;
END $$ LANGUAGE plpgsql;

-- впихивание ревизии, фактически -- обновление parent_id, ключа, имени и директории у файла
CREATE OR REPLACE FUNCTION insert_revision(
	_rootdir_guid UUID, _file_guid UUID, _revision_guid UUID, _parent_revision_guid UUID,
	_filename character varying(4096), _pubkey character varying(4096), _dir_guid UUID,
	_chunks integer, _drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE(r_error text, r_checkpoint bigint) AS $$
DECLARE
	_username "user".username%TYPE;
	_row record;

	-- хранилище (user_id, rootdir_id, directory_id, file_id, revision_id)
	_ur record;
	_w bigint;
BEGIN
	-- получение базовой информации
	BEGIN
		SELECT INTO _username username FROM _life_, options
		WHERE options."key" = 'life_mark'
			AND _life_.mark = options.value_u;
	EXCEPTION WHEN undefined_table THEN -- nothing
	END;
	IF _username IS NULL THEN
		RAISE EXCEPTION 'try to use begin_life() before call this';
	END IF;
	-- получение всякой информации
	SELECT
		"user".id AS user_id,
		rootdir.id AS rootdir_id,
		directory.id AS directory_id,
		file.id AS file_id,
		file_revision.id AS revision_id,
		CASE
		WHEN file.pubkey != '' OR file.filename != '' OR file_revision.parent_id != NULL
		THEN FALSE
		ELSE TRUE
		END AS permit
	INTO _ur
	FROM "user", rootdir, directory, file, file_revision
	WHERE
		"user".username = _username
		AND rootdir.user_id = "user".id
		AND rootdir.rootdir = _rootdir_guid
		AND directory.rootdir = rootdir.id
		AND directory.directory = _dir_guid
		AND file.rootdir_id = rootdir.id
		AND file.file = _file_guid
		AND file_revision.file_id = file.id
		AND file_revision.revision = _revision_guid;

	IF _ur IS NULL THEN
		-- уточняем из-за чего именно ошибка, возможно просто нет такой директории
		SELECT COUNT(*) INTO _w
		FROM "user", rootdir, directory
		WHERE "user".username = _username
			AND rootdir.user_id = "user".id
			AND rootdir.rootdir = _rootdir_guid
			AND directory.directory = _dir_guid;
		IF _w = 0 THEN
			r_error := concat('directory "', _dir_guid, '" not found in',
				'rootdir "', _rootdir_guid, '"');
			return;
		END IF;
		r_error := concat('revision "', _revision_guid,
			'" in rootdir "', _rootdir_guid, '" in file "', _file_guid,  '" not found');
		return;
	END IF;


	-- 1. проверка на перезапись
	IF _ur.permit = FALSE THEN
		r_error := concat('revision "', _file_guid, '" ',
			'already commited in rootdir "', _rootdir_guid, '" ',
			'file "', _file_guid, '"');
		return;
	END IF;

	-- 2. проверка количества чанков
	SELECT COUNT(*) INTO _w
	FROM file_chunk
	WHERE file_chunk.file_id = _ur.file_id
		AND file_chunk.revision_id  = _ur.revision_id;
	IF _w != _chunks THEN
		r_error := concat('different stored chunks count and wanted: ',
			_w, ' != ', _chunks, ' ',
			'in rootdir "', _rootdir_guid, '", ',
			'file "', _file_guid, '", ',
			'revision "', _revision_guid, '"');
		return;
	END IF;

	-- 3. обновление файла
	-- если имя не задано, то в будущем оно всё равно сможет переименовать файл
	-- а ключ нужно задавать обязательно (если он присутствует)
	IF _filename IS NOT NULL OR  _pubkey IS NOT NULL OR _dir_guid IS NOT NULL THEN
		UPDATE file
		SET
			filename = CASE WHEN _filename IS NULL THEN filename ELSE _filename END,
			pubkey = CASE WHEN _pubkey IS NULL THEN pubkey ELSE _pubkey END,
			directory_id =
				CASE WHEN _dir_guid IS NULL THEN directory_id ELSE _ur.directory_id END
		WHERE
			id = _ur.file_id;
	END IF;

	-- 4. обновление ревизии
	IF _parent_revision_guid IS NOT NULL THEN
		SELECT NULL INTO _row;
		SELECT * INTO _row FROM file_revision
		WHERE id = _ur.revision_id;
		IF _row IS NULL THEN
			r_error := concat('revision "', _parent_revision_guid, '" not found in ',
				'file "', _file_guid, '" ',
				'rootdir "', _rootdir_guid, '"');
			return;
		END IF;
		UPDATE file_revision SET parent_id = _row.id WHERE id = _ur.revision_id;
	END IF;
	-- TODO:
END $$ LANGUAGE plpgsql;

-- внесение нового чанка в таблицу (с упреждающей записью информации о файле и ревизии)
CREATE OR REPLACE FUNCTION insert_chunk(
	_rootdir_guid UUID, _file_guid UUID, _revision_guid UUID, _chunk_guid UUID, 
	_chunk_hash varchar(1024), _chunk_size integer, _chunk_offset integer,
	_address text, _drop_ _drop_ DEFAULT 'drop')
	RETURNS text AS $$
DECLARE
	_user_id bigint;
	_row record;
	-- user_id and rootdir_id
	_ur record;

	_dir_id bigint;
	_file_id bigint;
	_revision_id bigint;
BEGIN
	-- получение базовой информации
	BEGIN
		SELECT INTO _user_id user_id FROM _life_, options
		WHERE options."key" = 'life_mark' AND
			_life_.mark = options.value_u;
	EXCEPTION WHEN undefined_table THEN -- nothing
	END;
	IF _user_id IS NULL THEN
		RAISE EXCEPTION 'try to use begin_life() before call this';
	END IF;
	-- 1. Получить user_id и rootdir_id
	
	-- для начала нужно выяснить rootdir_id
	SELECT _user_id AS u, rootdir.id AS r INTO _ur FROM "user", rootdir
	WHERE
		rootdir.user_id = _user_id
		AND rootdir.rootdir = _rootdir_guid;
	IF _ur IS NULL THEN
		return concat('rootdir "', _rootdir_guid, '" not found');
	END IF;

	-- 2. получение file_id или вставка нового файла
	SELECT file.id INTO _file_id FROM file
	WHERE
		file.rootdir_id = _ur.r
		AND file.file = _file_guid;
	IF _file_id IS NULL THEN
		SELECT id INTO _dir_id FROM directory
		WHERE
			directory.rootdir_id = _ur.r
			AND directory.directory =
				(SELECT value_u FROM options WHERE "key" = 'incomplete_dir');
		WITH _row AS (
			INSERT INTO file (file, rootdir_id, dir_id)
			VALUES(
				_file_guid,
				_ur.r,
				_dir_id
			) RETURNING *
		) SELECT id INTO _file_id FROM _row;
	END IF;

	-- 3. извлечение revision_id
	SELECT id INTO _revision_id FROM file_revision
	WHERE
		file_revision.file_id = _file_id
		AND file_revision.revision = _revision_guid;
	IF _revision_id IS NULL THEN
		WITH _row AS (
			INSERT INTO file_revision (file_id, revision, chunks)
			VALUES (_file_id, _revision_guid, 0)
			RETURNING *
		) SELECT id INTO _revision_id FROM _row;
	END IF;

	-- 3. вставка нового чанка
	INSERT INTO file_chunk (revision_id, file_id, chunk, size, "offset", hash, address)
		VALUES (_revision_id, _file_id, _chunk_guid,
			_chunk_size, _chunk_offset, _chunk_hash, _address);
	-- TODO
	return NULL;
END $$ LANGUAGE plpgsql;

-- линковка чанка из старой ревизии с новой ревизией
CREATE OR REPLACE FUNCTION link_chunk(
	_rootdir_guid UUID, _file_guid UUID, _chunk_guid UUID,
	_new_chunk_guid UUID, _new_revision_guid UUID,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS text AS $$
DECLARE
	_username character varying(1024);
	_row record;
BEGIN
	-- получение базовой информации
	BEGIN
		SELECT INTO _username username FROM _life_, options
		WHERE options."key" = 'life_mark' AND
			_life_.mark = options.value_u;
	EXCEPTION WHEN undefined_table THEN -- nothing
	END;
	IF _username IS NULL THEN
		RAISE EXCEPTION 'try to use begin_life() before call this';
	END IF;
	-- 1. получить старые значение
	-- 2. смешать старые и новые значения
	SELECT
		_username AS username,
		rootdir.rootdir AS rootdir,
		file.file AS file,
		_new_chunk_guid AS chunk,
		_new_revision_guid AS revision,
		file_chunk.hash AS hash,
		file_chunk.size AS size,
		file_chunk.offset AS offset,
		file_chunk.address AS address
	INTO _row
	FROM "user", rootdir, file, file_chunk
	WHERE
		"user".username = _username
		AND rootdir.user_id = "user".id
		AND rootdir.rootdir = _rootdir_guid
		AND file.rootdir_id = rootdir.id
		AND file.file = _file_guid
		AND file_chunk.file_id = file.id
		AND file_chunk.chunk = _chunk_guid;
	-- 3. воспользоваться insert_chunk
	IF _row IS NULL THEN
		return concat('file "', _file_guid,
			'" not found in rootdir "',
			_rootdir_guid, '", file "', _file_guid, '"');
	END IF;
	return (SELECT insert_chunk(_row.username, _row.rootdir, _row.file, _row.chunk,
		_row.revision, _row.hash, _row.size, _row.offset, _row.address));
END $$ LANGUAGE plpgsql;

-- листинг лога
CREATE OR REPLACE FUNCTION log_list(_rootdir UUID, _checkpoint bigint,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE
	(
		r_type event_type,
		r_checkpoint bigint,
		r_rootdir UUID,
		r_file UUID,
		r_revision UUID,
		r_directory UUID,
		r_parent_revision UUID,
		r_name text,
		r_pubkey UUID,
		r_count integer
	) AS $$
DECLARE
	_ur record;
	_row record;
	_xrow record;
BEGIN
	-- получение базовой информации
	BEGIN
		SELECT INTO _ur user_id, device_id FROM _life_, options
		WHERE options."key" = 'life_mark' AND
			_life_.mark = options.value_u;
	EXCEPTION WHEN undefined_table THEN -- nothing
	END;
	IF _ur IS NULL THEN
		RAISE EXCEPTION 'try to use begin_life() before call this';
	END IF;

	-- варианты:
	-- TODO: 1. checkpoint IS NULL or == 0: отсылается текущее состояние
	FOR _row IN
		SELECT * FROM event
		WHERE user_id = _ur.user_id AND
			checkpoint > _checkpoint AND
			((_rootdir IS NOT NULL AND rootdir = _rootdir) OR
			(_rootdir IS NULL AND "type" = 'rootdir')) AND
			(device_id != _ur.device_id OR
			device_id IS NULL)
		ORDER BY checkpoint ASC
	LOOP
		r_type := _row."type";
		r_checkpoint := _row.checkpoint;
		r_rootdir := _row.rootdir;
		CASE _row."type"
		WHEN 'rootdir'
		THEN
			SELECT INTO _xrow title FROM rootdir_log
			WHERE id = _row.target_id;
			r_file := NULL;
			r_revision := NULL;
			r_directory := NULL;
			r_parent_revision := NULL;
			r_name := _xrow.title;
			r_pubkey := NULL;
			r_count := 0;
		WHEN 'directory'
		THEN
			SELECT INTO _xrow directory, path FROM directory_log
			WHERE id = _row.target_id;
			r_file := NULL;
			r_revision := NULL;
			r_directory := _xrow.directory;
			r_parent_revision := NULL;
			r_name := _xrow.path;
			r_pubkey := NULL;
			r_count := 0;
		WHEN 'file'
		THEN
			SELECT INTO _xrow
				file.file AS file,
				file_revision.revision AS revision,
				directory.directory AS directory,
				file_revision.parent_revision AS parent_revision,
				file_log.filename AS filename,
				file_log.pubkey AS pubkey,
				file_revision.chunks AS chunks
			FROM file_log, file, file_revision, directory
			WHERE
				file_log.id = _row.target_id AND
				file_revision.id = file_log.revision_id AND
				file.id = file_log.file_id AND
				directory.id = file_log.directory_id;
			r_file := _xrow.file;
			r_revision := _xrow.revision;
			r_directory := _xrow.directory;
			r_parent_revision := _xrow.parent_revision;
			r_name := _xrow.filename;
			r_pubkey := _xrow.pubkey;
			r_count := _xrow.chunks;
		END CASE;
		return next;
	END LOOP;
END $$ LANGUAGE plpgsql;

-- проверка имени пользователя
CREATE OR REPLACE FUNCTION check_user(_username "user".username%TYPE,
	_secret "user".username%TYPE, _drop_ _drop_ default 'drop')
	RETURNS boolean AS $$
BEGIN
	IF (SELECT COUNT(*) FROM "user" WHERE username = _username
		AND secret = _secret) = 1 THEN
		return True;
	END IF;
	return False;
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

-- event
CREATE TRIGGER tr_event_action BEFORE INSERT ON event
	FOR EACH ROW EXECUTE PROCEDURE event_action();

-- TODO: tr_file_log_action BEFORE INSERT

-- ?
CREATE TRIGGER tr_file_chunk_action_after AFTER INSERT ON file_chunk
	FOR EACH ROW EXECUTE PROCEDURE file_chunk_action_after();


INSERT INTO options ("key", value_c, value_u)
	VALUES ('trash_dir', '.Trash', '10000002-3004-5006-7008-900000000000');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('incomplete_dir', '.Incomplete',
		'20000002-3004-5006-7008-900000000000');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('1_rootdir', 'First', 
		'00000001-2003-5406-7008-900000000000');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('2_rootdir', 'Second',
		'11000001-2003-5406-7008-900000000000');
-- опция для костыля, что бы не возникло наложения данных из таблицы _life_ при обновлении бд
INSERT INTO options ("key", value_u)
	VALUES ('life_mark', gen_random_uuid());

