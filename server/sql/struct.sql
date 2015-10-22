/*	vim: syntax=pgsql
	текущая версия задаётся в fepserver_installed()

! При изменении полей в таблицах не забывай исправлять процедуру begin_life


 поле результата r_error содержит строку вида "n:message" где n:
 1: критическая ошибка
 2: ну как бы вот
 3: уведомление
*/

CREATE OR REPLACE FUNCTION fepserver_installed()
	RETURNS text AS $$
DECLARE
	_struct_version_value text;
	_exc_str text;
BEGIN
	/* версия структуры */
	SELECT INTO _struct_version_value '6';

	/* проверка pgcrypto, на всякий случай
	// уже не нужно, для примера
	BEGIN
		PERFORM gen_random_uuid();
	EXCEPTION WHEN undefined_function THEN
		GET STACKED DIAGNOSTICS _exc_str = MESSAGE_TEXT;
		RAISE EXCEPTION
			'check pgcrypto: %', _exc_str
			USING HINT = 'try to `CREATE EXCEPTION pgcrypto` in this database';
	END; */

	RETURN _struct_version_value;
END $$ LANGUAGE plpgsql;

/* костыли */
CREATE OR REPLACE FUNCTION gen_random_uuid()
	RETURNS uuid AS $$
BEGIN
	return (SELECT md5(random()::text || clock_timestamp()::text)::uuid);
END $$ LANGUAGE plpgsql IMMUTABLE;

/* обновление табличного пространства */

-- удаление таблиц не должно вызывать NOTICE с нерзрешёнными CONSTRAINT
DROP TABLE IF EXISTS file_temp CASCADE;
DROP TABLE IF EXISTS file_meta CASCADE;
DROP TABLE IF EXISTS file_chunk CASCADE;
DROP TABLE IF EXISTS file_revision CASCADE;
DROP TABLE IF EXISTS options CASCADE;
DROP TABLE IF EXISTS file CASCADE;
DROP TABLE IF EXISTS directory CASCADE;
DROP TABLE IF EXISTS directory_log CASCADE;
DROP TABLE IF EXISTS event CASCADE;
DROP TABLE IF EXISTS rootdir CASCADE;
DROP TABLE IF EXISTS rootdir_log CASCADE;
DROP TABLE IF EXISTS device CASCADE;
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
DROP SEQUENCE IF EXISTS device_seq CASCADE;
DROP SEQUENCE IF EXISTS file_meta_seq CASCADE;
DROP SEQUENCE IF EXISTS event_checkpoint_seq CASCADE;
DROP SEQUENCE IF EXISTS file_chunk_group_seq CASCADE;
DROP SEQUENCE IF EXISTS options_seq CASCADE;

DROP TYPE IF EXISTS _drop_ CASCADE;
DROP TYPE IF EXISTS event_type CASCADE;

-- костыль для гроханья всех хранимых процедур
CREATE TYPE _drop_ AS ENUM ('drop');

CREATE SEQUENCE user_seq;
CREATE TABLE IF NOT EXISTS "user"
(
	id bigint NOT NULL DEFAULT nextval('user_seq') PRIMARY KEY,
	created timestamp with time zone NOT NULL DEFAULT now(),
	username varchar(1024) NOT NULL CHECK(char_length(username) > 0),
	secret varchar(96) NOT NULL,
	UNIQUE(username)
);


CREATE SEQUENCE device_seq;
CREATE TABLE IF NOT EXISTS device
(
	id bigint NOT NULL DEFAULT nextval('device_seq') PRIMARY KEY,
	user_id bigint NOT NULL REFERENCES "user"(id),
	reg_time timestamp with time zone NOT NULL DEFAULT now(),
	last_time timestamp with time zone NOT NULL DEFAULT now(),
	device bigint NOT NULL,
	UNIQUE(device, user_id)
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

	quota bigint NOT NULL DEFAULT 0,

	UNIQUE (user_id, rootdir)
);

CREATE SEQUENCE options_seq;
CREATE TABLE IF NOT EXISTS options
(
	id bigint NOT NULL DEFAULT nextval('options_seq') PRIMARY KEY,
	"key" varchar(16) NOT NULL CHECK(char_length("key") > 0),
	value_c varchar(64) DEFAULT NULL,
	value_i integer DEFAULT NULL,
	value_u UUID DEFAULT NULL,
	UNIQUE ("key")
);

-- directory: переименование/удаление директории
-- file: создание/удаление/ревизия файла
-- rootdir: создание/удаление корневой директории
CREATE TYPE event_type AS ENUM ('directory',
	'file_meta', 'file_revision',
	'rootdir');

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
	device_id bigint DEFAULT NULL,

	-- спрятать ли событие при выводе списка клиенту
	hidden boolean NOT NULL DEFAULT FALSE,
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
	
	-- финализирующая запись (при удалении)
	-- костыль для триггера tr_directory_log_action
	fin boolean NOT NULL DEFAULT FALSE,

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

	UNIQUE(rootdir_id, directory)
);

-- "удалённые" директории не должны учитываться при индексации
CREATE UNIQUE INDEX directory_unque_path_idx ON directory (rootdir_id, path)
	WHERE strpos(path, '/.Trash') != 1;

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
	filename varchar(4096) DEFAULT NULL,

	deleted boolean DEFAULT FALSE,
	uploaded boolean DEFAULT FALSE,

	UNIQUE(rootdir_id, file)
);

/* таблица для сохранения временных значений файлов, недокачанных, к примеру */
CREATE TABLE IF NOT EXISTS file_temp
(
	id bigint NOT NULL REFERENCES file(id) ON DELETE CASCADE,
	directory UUID DEFAULT NULL,
	directory_id bigint DEFAULT NULL,
	filename varchar(4096) DEFAULT NULL,
	pubkey varchar(4096) DEFAULT NULL,
	chunks integer DEFAULT NULL
);

CREATE OR REPLACE FUNCTION _check_is_trash(_rootdir_id bigint,
	_directory_id bigint,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS boolean AS $$
DECLARE
	_r record;
BEGIN
	SELECT * INTO _r
	FROM directory, options
	WHERE
		options."key" = 'trash_dir' AND
		directory.rootdir_id = _rootdir_id AND
		directory.directory = options.value_u AND
		directory.id = _directory_id;

	IF _r IS NOT NULL THEN
		return TRUE;
	END IF;
	return FALSE;
END $$ LANGUAGE plpgsql IMMUTABLE;

CREATE UNIQUE INDEX file_unique_path_idx ON file(directory_id, filename)
	WHERE _check_is_trash(rootdir_id, directory_id);

CREATE SEQUENCE file_revision_seq;
CREATE TABLE IF NOT EXISTS file_revision
(
	id bigint DEFAULT nextval('file_revision_seq') PRIMARY KEY,
	file_id bigint NOT NULL REFERENCES file(id) ON DELETE CASCADE,

	checkpoint bigint DEFAULT NULL,
	event_id bigint DEFAULT NULL REFERENCES event(id),

	revision UUID NOT NULL,
	parent_id bigint DEFAULT NULL REFERENCES file_revision(id),

	-- количество чанков в ревизии
	chunks integer NOT NULL DEFAULT 0,
	-- количество сохранённых чанков
	stored_chunks integer NOT NULL DEFAULT 0,

	-- хак для индикации завершения сборки ревизии
	fin boolean NOT NULL DEFAULT FALSE,
	UNIQUE(file_id, revision)
);

CREATE SEQUENCE file_meta_seq;
CREATE TABLE IF NOT EXISTS file_meta
(
	id bigint DEFAULT nextval('file_meta_seq') PRIMARY KEY,
	time timestamp with time zone NOT NULL DEFAULT now(),

	file_id bigint NOT NULL REFERENCES file(id) ON DELETE CASCADE,
	revision_id bigint NOT NULL REFERENCES file_revision(id),

	checkpoint bigint DEFAULT NULL,
	event_id bigint DEFAULT NULL REFERENCES event(id),

	-- если оба поля NULL, значит файл удалён
	filename varchar(4096) DEFAULT NULL,
	directory_id bigint DEFAULT NULL,

	UNIQUE(checkpoint)
);

CREATE SEQUENCE file_chunk_group_seq;
CREATE SEQUENCE file_chunk_seq;
CREATE TABLE IF NOT EXISTS file_chunk
(
	id bigint DEFAULT nextval('file_chunk_seq') PRIMARY KEY,
	revision_id bigint NOT NULL REFERENCES file_revision(id),

	file_id bigint NOT NULL REFERENCES file(id) ON DELETE CASCADE,

	chunk UUID NOT NULL,

	/* параметры чанка */
	size integer NOT NULL,
	"offset" integer NOT NULL,
	hash character varying(256) NOT NULL,
	-- путь к файлу
	address text NOT NULL,

	driver text DEFAULT NULL,

	-- костыль, нужен для группирования одинаковых чанков
	-- location_group -- идентификатор адреса
	-- по которому расположен чанк
	-- теоретически, может произойти коллизия хэша
	-- у двух файлов с разным содержимым
	-- потому пологаться только на хэш чанка нельзя
	-- нужно учитывать его принадлежность к пользователю
	-- и в какой из рутдир он расположен
	rootdir_id bigint NOT NULL REFERENCES rootdir(id),
	location_group bigint NOT NULL,

	UNIQUE(file_id, chunk)
);

/* триггеры и процедурки */

-- чистка event при удалении из file_meta и file_revision
CREATE OR REPLACE FUNCTION file_delete()
	RETURNS trigger AS $$
BEGIN
	RAISE EXCEPTION 'use `UPDATE file SET deleted = TRUE;`';
	return old;
END $$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION file_update()
	RETURNS trigger AS $$
DECLARE
	_status boolean;
BEGIN
	IF new.deleted = TRUE AND old.deleted = FALSE THEN
		_status := TRUE;
	ELSE
		_status := FALSE;
	END IF;

	-- обновление event при изменении статуса
	UPDATE event SET hidden = _status
	WHERE
		hidden != _status AND
		("type" = 'file_meta' AND
			target_id IN
				(SELECT id FROM file_meta WHERE file_id = old.id)) OR
		("type" = 'file_revision' AND
			target_id IN
				(SELECT id from file_revision WHERE file_id = old.id));
	return new;
END $$ LANGUAGE plpgsql;

-- автозаполнение полей
CREATE OR REPLACE FUNCTION event_action()
	RETURNS trigger AS $$
DECLARE
	_user record;
BEGIN

	IF new.device_id IS NULL OR new.user_id IS NULL THEN
		BEGIN
			-- проверочка нужна что бы не произошло лишнего смешения
			SELECT INTO _user _life_.device_id, _life_.user_id
			FROM _life_, "user", options
			WHERE options."key" = 'life_mark' AND
				_life_.mark = options.value_u;
			IF _user.device_id IS NOT NULL THEN
				new.device_id := _user.device_id;
			END IF;
			IF _user.user_id IS NOT NULL THEN
				new.user_id := _user.user_id;
			END IF;
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

-- внесение болванки (без checkpoint) в directory_log при удалении директории
CREATE OR REPLACE FUNCTION directory_delete()
	RETURNS trigger AS $$
BEGIN
	--INSERT INTO directory_log (rootdir_id, directory_id, directory, fin)
	--VALUES (old.rootdir_id, old.id, old.directory, TRUE);
	return old;
END $$ LANGUAGE plpgsql;

-- по принципу rootdir_log_action/rootdir_log_action_after
CREATE OR REPLACE FUNCTION directory_log_action()
	RETURNS TRIGGER AS $$
DECLARE
	_row record;
	_dirs bigint[];
	_trash_id bigint;
	i integer;
BEGIN
	-- причёсывание пути, если вдруг прислали ошмёток (как?)
	IF substring(NEW.path from 1 for 1) != '/' THEN
		NEW.path = concat('/', NEW.path);
	END IF;

	-- если финализация, то дальнейшая обработка не нужна
	IF new.fin = TRUE THEN
		return new;
	END IF;

	-- удаление происходит в несколько стадий:
	-- 1. пометка всех файлов как "deleted" и перенос их в .Trash
	-- 2. удаление самой директории
	IF new.path IS NULL THEN
		-- проверяем что не хотят удалить системную директорию
		IF (SELECT COUNT(*)
				FROM options
				WHERE
					"key" LIKE '%\_dir' AND
					value_u = new.directory) != 0 THEN
			RAISE EXCEPTION 'system directory guard dissatisfied';
			return new;
		END IF;

		-- получение id треша
		SELECT directory.id FROM options, directory
		INTO _trash_id
		WHERE
			options."key" = 'trash_dir' AND
			directory.rootdir_id = new.rootdir_id AND
			directory.directory = options.value_u;

		-- т.к. path IS NULL, то нужно выбрать последнее имя директории из бд
		SELECT
			directory.path AS path,
			directory.id AS directory_id
		INTO _row
		FROM directory
		WHERE
			directory.rootdir_id = new.rootdir_id AND
			directory.directory = new.directory;

		IF _row IS NULL THEN
			RAISE EXCEPTION 'invalid directory data: uuid %',
				new.directory;
			return new;
		END IF;

		new.path = _row.path;
		new.directory_id = _row.directory_id;

		-- сбор всех директорий на удаление
		SELECT array_agg(id) INTO _dirs
		FROM directory
		WHERE
			directory.path LIKE new.path || '%' AND
			directory.id != new.directory_id;

		-- принудительное "удаление" файлов
		UPDATE file
		SET
			directory_id = _trash_id,
			deleted = TRUE
		WHERE
			file.directory_id = ANY(_dirs::bigint[]) OR
			file.directory_id = new.directory_id;
	
		SELECT COUNT(*) AS c INTO _row
		FROM file WHERE file.directory_id = ANY(_dirs::bigint[]);

		-- удаление директорий
		DELETE FROM directory WHERE id = ANY(_dirs::bigint[]);

		new.path := NULL;
		new.fin := TRUE;
	ELSE

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
	_logs bigint[];
BEGIN

	IF new.path IS NULL THEN
		IF new.directory_id IS NULL THEN
			RAISE EXCEPTION 'incomplete directory_log_action: no directory_id';
			return new;
		END IF;

		DELETE FROM directory WHERE id = new.directory_id;

		-- нужно спрятать все события по этой директории из лога
		UPDATE event SET hidden = TRUE
		WHERE "type" = 'directory' AND
			target_id IN
				(SELECT id
					FROM directory_log
					WHERE directory_log.directory_id = new.directory_id) AND
			target_id != new.id;
		
		return new;
	END IF;

	-- дальнейшая обработка не нужна
	IF new.fin = TRUE THEN
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
	UPDATE file_revision SET stored_chunks = (stored_chunks + 1)
	WHERE file_revision.id = new.revision_id;
	return new;
END $$ LANGUAGE plpgsql;


-- обновление полей в file, добавление записи в event
CREATE OR REPLACE FUNCTION file_meta_action()
	RETURNS trigger AS $$
DECLARE
	_rootdir rootdir.rootdir%TYPE;
	_r record;
	_trash_id bigint;
BEGIN
	-- получение id треша
	SELECT directory.id
	FROM options, directory, file
	INTO _trash_id
	WHERE
		options."key" = 'trash_dir' AND
		file.id = new.file_id AND
		directory.rootdir_id = file.rootdir_id AND
		directory.directory = options.value_u;

	IF new.directory_id IS NULL AND new.filename IS NULL OR
		new.directory_id = _trash_id THEN
		-- удаление, обновляем соотвествующее поле
		UPDATE file SET deleted = TRUE WHERE id = new.file_id;
	ELSE
		-- обновление значений в file
		UPDATE file SET filename = new.filename, directory_id = new.directory_id
		WHERE id = new.file_id;
	END IF;

	-- костыль: если checkpoint == 0, то события в event не создаётся
	IF new.checkpoint IS NULL OR new.checkpoint != 0 THEN
		-- получение rootdir_guid
		SELECT INTO _rootdir rootdir.rootdir FROM file, rootdir
		WHERE file.id = new.file_id AND
			rootdir.id = file.rootdir_id;
		-- добавление евента в лог
		WITH _row AS (
			INSERT INTO event (rootdir, "type", target_id)
			VALUES (_rootdir, 'file_meta', new.id)
			RETURNING *
		) SELECT INTO _r checkpoint, id FROM _row;
		new.checkpoint := _r.checkpoint;
		new.event_id = _r.id;
	END IF;

	IF new.checkpoint = 0 THEN
		new.checkpoint := NULL;
	END IF;

	return new;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION file_revision_update_action()
	RETURNS trigger AS $$
DECLARE
	_user record;
	_rootdir UUID;
	_r record;
BEGIN
	-- костыль -_-
	-- происходит инкремент только счётчика, но не обновления
	-- данных ревизии
	IF new.chunks = old.chunks AND new.stored_chunks = (old.stored_chunks + 1)
		THEN
		return new;
	END IF;

	-- файл собрался
	IF new.chunks = new.stored_chunks THEN
		SELECT INTO _rootdir rootdir FROM rootdir, file
		WHERE file.id = new.file_id AND
			rootdir.id = file.rootdir_id;
		-- нужно добавить запись в event
		WITH _row AS (
			INSERT INTO event (rootdir, "type", target_id)
			VALUES (_rootdir, 'file_revision', new.id)
			RETURNING *
		) SELECT INTO _r checkpoint, id FROM _row;
		new.checkpoint = _r.checkpoint;
		new.event_id = _r.id;
	END IF;

	--IF new.chunks = old.stored_chunks
	return new;
END $$ LANGUAGE plpgsql;

/* упрощалки жизни */

-- облегчающий жизнь костыль, должен вызываться перед началом всех
-- "простых" операций, сохраняет значение текущего имени пользователя
-- и id устройства
CREATE OR REPLACE FUNCTION begin_life(_username "user".username%TYPE,
	_device_id event.device_id%TYPE, _drop_ _drop_ DEFAULT 'drop')
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
		device_id bigint
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

-- впихивание ревизии, фактически -- обновление parent_id, ключа, имени и директории у файла
--  _prepare указывает на то, что это не есть завершение загрузки файла
-- а лишь сохранение данных по файлу
create or replace function insert_revision(
	_rootdir_guid uuid,
	_file_guid uuid,
	_revision_guid uuid,
	_parent_revision_guid uuid,
	_filename character varying(4096),
	_pubkey character varying(4096),
	_dir_guid uuid,
	_chunks integer,
	_prepare boolean default FALSE,
	_drop_ _drop_ default 'drop')
	returns table(r_error text, r_checkpoint bigint) as $$
DECLARE
	_row record;
	_parent record;

	-- хранилище (user_id, rootdir_id, directory_id, file_id, revision_id)
	_ur record;
	_w bigint;
BEGIN
	-- получение информации о файле
	SELECT
		e.rootdir_id AS rootdir_id,
		e.directory_id AS directory_id,
		file.id AS file_id,
		file_revision.id AS revision_id,
		NOT file_revision.fin AS permit
	INTO _ur
	FROM (SELECT
			r_rootdir_id AS rootdir_id,
			directory.id AS directory_id
		FROM directory, life_data(_rootdir_guid)
		WHERE 
			directory.rootdir_id = r_rootdir_id AND
			directory.directory = _dir_guid) AS e
	LEFT JOIN file
	ON 
		file.rootdir_id = e.rootdir_id AND
		file.file = _file_guid
	LEFT JOIN file_revision
	ON
		file_revision.file_id = file.id AND
		file_revision.revision = _revision_guid;

	IF _ur IS NULL THEN
		-- уточняем из-за чего именно ошибка, возможно просто нет такой директории
		SELECT COUNT(*) INTO _w
		FROM rootdir, directory
		WHERE rootdir.user_id = user_id
			AND rootdir.rootdir = _rootdir_guid
			AND directory.directory = _dir_guid;
		IF _w = 0 THEN
			r_error := concat('1:directory "', _dir_guid, '" not found in',
				'rootdir "', _rootdir_guid, '"');
			return next;
			return;
		END IF;
		r_error := concat('1:wtf in revision "', _revision_guid,
			'" in rootdir "', _rootdir_guid, '" in file "', _file_guid,  '" not found');
		return next;
		return;
	END IF;

	-- проверка существования файла (и создание его)
	IF _ur.file_id IS NULL THEN
		WITH _x AS (
			INSERT INTO file (file, rootdir_id, directory_id)
			VALUES (_file_guid, _ur.rootdir_id, _ur.directory_id)
			RETURNING *
		) SELECT id INTO _ur.file_id FROM _x;
	END IF;

	-- и ревизии
	IF _ur.revision_id IS NULL THEN
		-- и добавляем ревизию, если таковых нет
		WITH _x AS (
			INSERT INTO file_revision (file_id, revision, chunks)
			VALUES (_ur.file_id, _revision_guid, 0)
			RETURNING *
		) SELECT id INTO _ur.revision_id FROM _x;
	END IF;


	-- 0.5 проверка наличия ревизии
	SELECT INTO _parent id, revision
	FROM file_revision
	WHERE fin = TRUE AND
		file_id = _ur.file_id AND
		id = (SELECT MAX(id) FROM file_revision WHERE file_id = _ur.file_id AND fin = TRUE);

	IF _parent IS NOT NULL AND
		(_parent_revision_guid IS NULL OR
			_parent.revision != _parent_revision_guid) THEN
		r_error := concat('1:last revision: ', _parent.revision,
			' offered: "', _parent_revision_guid, '"');
		return next;
		return;
	END IF;

	IF _parent IS NULL AND _parent_revision_guid IS NOT NULL THEN
		r_error := concat('1:parent revision ', _parent_revision_guid, ' not found');
		return next;
		return;
	END IF;

	-- 1. проверка на перезапись
	IF _ur.permit = FALSE THEN
		r_error := concat('1:revision "', _revision_guid, '" ',
			'already commited in rootdir "', _rootdir_guid, '" ',
			'file "', _file_guid, '"');
		return next;
		return;
	END IF;

	-- если это подготовка, то выполнение всего следующего кода не нужно
	IF _prepare = TRUE THEN
		INSERT INTO file_temp SELECT
			_ur.file_id,
			_dir_guid,
			_ur.directory_id,
			_filename,
			_pubkey,
			_chunks;
		return next;
		return;
	END IF;

	-- получение сохранённой информации о файле
	SELECT * INTO _row
	FROM file_temp
	WHERE id = _ur.revision_id;

	IF _row IS NOT NULL THEN
		_dir_guid := COALESCE(_row.directory, _dir_guid);
		_filename := COALESCE(_row.filename, _filename);
		_pubkey := COALESCE(_row.pubkey, _pubkey);
		_chunks := COALESCE(_row.chunks, _chunks);
	END IF;

	-- 2. проверка количества чанков
	SELECT stored_chunks INTO _w
	FROM file_revision
	WHERE id = _ur.revision_id;
	IF _w != _chunks OR _w IS NULL THEN
		r_error := concat('1:different stored chunks count and wanted: ',
			_w, ' != ', _chunks, ' ',
			'in rootdir "', _rootdir_guid, '", ',
			'file "', _file_guid, '", ',
			'revision "', _revision_guid, '"');
		return next;
		return;
	END IF;

	-- 3. обновление файла
	WITH __x AS (
		UPDATE file
		SET
			pubkey = CASE WHEN _pubkey IS NULL THEN pubkey ELSE _pubkey END
		WHERE id = _ur.file_id
		RETURNING *
	) INSERT INTO file_meta
	SELECT nextval('file_meta_seq'),
		now(),
		_ur.file_id,
		_ur.revision_id,
		0,
		NULL,
		_filename, _ur.directory_id
	FROM __x
	WHERE
		__x.filename != _filename OR
		__x.directory_id != _ur.directory_id OR
		(__x.filename IS NULL AND _filename IS NOT NULL) OR
		(__x.directory_id IS NULL AND _ur.directory_id IS NOT NULL) OR
		(__x.filename IS NOT NULL AND _filename IS NULL) OR
		(__x.directory_id IS NOT NULL AND _ur.directory_id IS NULL);

	-- 4. обновление ревизии
	IF _parent_revision_guid IS NOT NULL THEN
		SELECT NULL INTO _row;
		SELECT * INTO _row FROM file_revision
		WHERE revision = _parent_revision_guid;
		IF _row IS NULL THEN
			r_error := concat('1:revision "', _parent_revision_guid,
				'" not found in file "', _file_guid, '" ',
				'rootdir "', _rootdir_guid, '"');
			return next;
			return;
		END IF;
		WITH _row AS (
			UPDATE file_revision
			SET parent_id = _row.id, chunks = _chunks, fin = TRUE
			WHERE id = _ur.revision_id
			RETURNING *
		) SELECT INTO r_checkpoint checkpoint FROM _row;
	ELSE
		WITH _row AS (
			UPDATE file_revision SET chunks = _chunks, fin = TRUE
			WHERE id = _ur.revision_id
			RETURNING *
		) SELECT INTO r_checkpoint checkpoint FROM _row;
	END IF;

	-- удаление не нужных данных
	DELETE FROM file_temp WHERE id = _ur.file_id;

	return next;
END $$ LANGUAGE plpgsql;

-- внесение нового чанка в таблицу (с упреждающей записью информации о файле и ревизии)
CREATE OR REPLACE FUNCTION insert_chunk(
	_rootdir_guid UUID, _file_guid UUID, _revision_guid UUID, _chunk_guid UUID,
	_chunk_hash varchar(1024), _chunk_size integer, _chunk_offset integer,
	_address text, _drop_ _drop_ DEFAULT 'drop')
	RETURNS text AS $$
DECLARE
	_user_id "user".id%TYPE;
	_row record;
	-- user_id and rootdir_id
	_ur record;

	_dir_id bigint;
	_file_id bigint;
	_revision_id bigint;
	_location_group bigint;
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
			INSERT INTO file (file, rootdir_id, directory_id)
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

	-- 4. подбор location_group
	SELECT location_group
	INTO _location_group
	FROM file_chunk
	WHERE file_chunk.hash = _chunk_hash AND
		file_chunk.size = _chunk_size AND
		file_chunk.rootdir_id = _ur.r;

	IF _location_group IS NULL THEN
		SELECT nextval('file_chunk_group_seq') INTO _location_group;
	END IF;

	-- 5. вставка нового чанка
	INSERT INTO file_chunk
		(revision_id, file_id, chunk, size, "offset", hash, address,
			rootdir_id, location_group)
		VALUES (_revision_id, _file_id, _chunk_guid,
			_chunk_size, _chunk_offset, _chunk_hash, _address,
			_ur.r,
			_location_group);

	return NULL;
END $$ LANGUAGE plpgsql;

-- линковка чанка из старой ревизии с новой ревизией
CREATE OR REPLACE FUNCTION link_chunk(
	_rootdir_guid UUID, _file_guid UUID, _chunk_guid UUID,
	_new_chunk_guid UUID, _new_revision_guid UUID,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS text AS $$
DECLARE
	_user_id "user".id%TYPE;
	_row record;
BEGIN
	-- FIXME: возникнут проблемы при переносе
	-- чанков, расположенных не в кеше (с полем "driver")

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
	-- 1. получить старые значение
	-- 2. смешать старые и новые значения
	SELECT
		rootdir.rootdir AS rootdir,
		file.file AS file,
		_new_chunk_guid AS chunk,
		_new_revision_guid AS revision,
		file_chunk.hash AS hash,
		file_chunk.size AS size,
		file_chunk.offset AS offset,
		file_chunk.address AS address
	INTO _row
	FROM rootdir, file, file_chunk
	WHERE rootdir.user_id = _user_id
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
	return (SELECT insert_chunk(_row.rootdir, _row.file, _row.revision,
		_row.chunk, _row.hash, _row.size, _row.offset, _row.address));
END $$ LANGUAGE plpgsql;

-- возвращает информацию о текущем пользователе
-- для существующей версии бд (по life_mark)
CREATE OR REPLACE FUNCTION life_data(_rootdir rootdir.rootdir%TYPE DEFAULT NULL,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE
	(
		r_username "user".username%TYPE,
		r_user_id "user".id%TYPE,
		r_device_id event.device_id%TYPE,
		r_rootdir_id rootdir.id%TYPE
	) AS $$
DECLARE
	_r record;
BEGIN
	BEGIN
		SELECT
			_life_.*,
			CASE WHEN _rootdir IS NULL THEN NULL ELSE rootdir.id END
				AS rootdir_id
		INTO _r
		FROM options, _life_, "user"
		LEFT JOIN rootdir
		ON CASE WHEN _rootdir IS NOT NULL THEN
				rootdir.user_id = "user".id AND
				rootdir.rootdir = _rootdir
			ELSE TRUE
			END
		WHERE options."key" = 'life_mark' AND
			_life_.mark = options.value_u AND
			"user".id = _life_.user_id AND
			"user".username = _life_.username;
	EXCEPTION WHEN undefined_table THEN -- nothing
	END;
	IF _r IS NULL THEN
		RAISE EXCEPTION 'try to use begin_life() before call this';
	END IF;
	IF _r.rootdir_id IS NULL AND _rootdir IS NOT NULL THEN
		RAISE EXCEPTION 'rootdir % not owned by %', _rootdir, _r.username;
	END IF;
	r_username := _r.username;
	r_user_id := _r.user_id;
	r_device_id := _r.device_id;
	r_rootdir_id := _r.rootdir_id;
	return next;
END $$ LANGUAGE plpgsql;

-- переименование и перемещение файла
CREATE OR REPLACE FUNCTION update_file(_rootdir UUID, _file UUID,
	_new_directory UUID, _new_filename file.filename%TYPE)
	RETURNS TABLE(r_error text, r_checkpoint bigint) AS $$
DECLARE
	_rfile record;
	_revision_id file_revision.id%TYPE;
BEGIN
	-- получение базовой информации о файле

	SELECT INTO _rfile
		file.id,
		filename,
		directory_id,
		directory,
		file.rootdir_id
	FROM file, directory, life_data(_rootdir)
	WHERE
		file.rootdir_id = r_rootdir_id AND
		file.file = _file AND
		directory.id = file.directory_id;

	IF _rfile IS NULL THEN
		r_error := concat('1:file ', _file, ' not found in rootdir ', _rootdir);
		return next;
		return;
	END IF;

	IF _new_filename = _rfile.filename AND _new_directory = _rfile.directory THEN
		SELECT INTO r_checkpoint MAX(checkpoint)
		FROM file_log
		WHERE file_id = _rfile.id;
		return next;
		return;
	END IF;

	IF _new_filename IS NULL AND _new_directory IS NULL THEN
		-- "удаление"
		_rfile.filename := NULL;
		_rfile.directory_id := NULL;
	ELSE
		IF _new_filename IS NOT NULL THEN
			_rfile.filename := _new_filename;
		END IF;

		IF _new_directory IS NOT NULL THEN
			SELECT INTO _rfile.directory_id id FROM directory
			WHERE directory.rootdir_id = _rfile.rootdir_id AND
				directory.directory = _new_directory;
		END IF;

		IF _rfile.directory_id IS NULL THEN
			r_error := concat('1:directory ', _new_directory, ' not found in rootdir ',
				_rootdir);
			return next;
			return;
		END IF;
	END IF;

	-- получение текущей ревизии
	SELECT INTO _revision_id MAX(id) FROM file_revision
	WHERE fin = TRUE AND file_id = _rfile.id;

	-- внесение новых значений
	WITH _row AS (
		INSERT INTO file_meta (file_id, revision_id, filename, directory_id)
		VALUES (_rfile.id, _revision_id, _rfile.filename, _rfile.directory_id)
		RETURNING *
	) SELECT INTO r_checkpoint checkpoint FROM _row;

	return next;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION directory_create(_rootdir UUID, _directory UUID,
	_dirname TEXT,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE (r_error text, r_checkpoint bigint) AS $$
DECLARE
	_ur record;
BEGIN
	-- сбор информации о пользователе
	SELECT
		r_username AS username,
		r_user_id AS user_id,
		r_rootdir_id AS rootdir_id
	INTO _ur
	FROM life_data(_rootdir);

	-- проверка существования директории (и это не переименование)
	WITH _row AS (
		SELECT directory_log.* FROM directory, directory_log
		WHERE directory.rootdir_id = _ur.rootdir_id AND
			directory.directory = _directory AND
			directory.path = _dirname AND
			directory_log.id = directory.log_id
	) SELECT checkpoint INTO r_checkpoint FROM _row;

	IF r_checkpoint IS NOT NULL THEN
		r_error := '3:Directory already updated';
		return next;
		return;
	END IF;

	-- впихивание директории и возврат checkpoint
	WITH _xrow AS (
		INSERT INTO directory_log (rootdir_id, directory, path)
		VALUES (_ur.rootdir_id, _directory, _dirname)
		RETURNING *
	) SELECT checkpoint INTO r_checkpoint FROM _xrow;

	--IF r_checkpoint IS NULL THEN
	--	маловероятно что не смог пройти insert
	--	и сейчас нет представлений почему это могло случиться
	--	r_error := concat(' ');
	--END IF;
	return next;
	return;
END $$ LANGUAGE plpgsql;

-- информация о файле (ревизии)
-- если _revision IS NULL, то извлекается последняя ревизия
CREATE OR REPLACE FUNCTION file_get(_rootdir UUID, _file UUID, _revision UUID,
	uncompleted boolean DEFAULT FALSE,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_revision file_revision.revision%TYPE,
		r_parent file_revision.revision%TYPE,
		r_directory directory.directory%TYPE,
		r_filename file.filename%TYPE,
		r_pubkey file.pubkey%TYPE,
		r_chunks file_revision.chunks%TYPE,
		r_stored_chunks file_revision.stored_chunks%TYPE
	)
	AS $$
DECLARE
	_r record;
	_rev record;
BEGIN
	-- выборка файла и директории
	SELECT
		t.file_id,
		t.rootdir_id,
		t.file_guid,
		COALESCE(file_temp.directory, directory.directory) AS directory_guid,
		COALESCE(file_temp.filename, t.filename) AS filename,
		COALESCE(file_temp.pubkey, t.pubkey) AS pubkey
	FROM (
		SELECT
			file.id AS file_id,
			r_rootdir_id AS rootdir_id,
			file.file AS file_guid,
			file.filename AS filename,
			file.directory_id AS directory_id,
			file.pubkey AS pubkey
		FROM life_data(_rootdir), file
		WHERE
			file.rootdir_id = r_rootdir_id AND
			file.file = _file
		) AS t
	INTO _r
	LEFT JOIN file_temp ON file_temp.id = t.file_id
	LEFT JOIN directory ON directory.id = t.directory_id;

	IF _r IS NULL THEN
		r_error := concat('1:file "', _file, '" in rootdir "', _rootdir, '" ',
			'not found');
		return next;
		return;
	END IF;

	-- выборка ревизии
	-- если указана конкретная ревизиая, то выдаём её,
	-- иначе выдаём последнюю
	SELECT
		file_revision.revision AS revision_guid,
		file_revision.chunks AS chunks,
		file_revision.stored_chunks AS stored_chunks,
		parent_revision.revision AS parent_guid
	INTO _rev
	FROM file_revision
	LEFT JOIN file_revision AS parent_revision
	ON parent_revision.id = file_revision.parent_id
	WHERE
		file_revision.file_id = _r.file_id AND
		CASE
			WHEN _revision IS NOT NULL
				THEN file_revision.revision = _revision
			ELSE
				TRUE
		END AND
		file_revision.fin = NOT COALESCE(uncompleted, False)
	ORDER BY file_revision.checkpoint DESC LIMIT 1;

	IF _rev IS NULL THEN
		r_error := concat('1:revision "', _revision, '" for file "', _file, '" ',
			'in rootdir "', _rootdir, '" not found');
		return next;
		return;
	END IF;

	r_revision := _rev.revision_guid;
	r_parent := _rev.parent_guid;
	r_directory := _r.directory_guid;
	r_filename := _r.filename;
	r_pubkey := _r.pubkey;
	r_chunks := _rev.chunks;
	r_stored_chunks := _rev.stored_chunks;
	return next;
END $$ LANGUAGE plpgsql;

-- получение информации о чанке
CREATE OR REPLACE FUNCTION chunk_get(_rootdir UUID, _file UUID,
	_chunk UUID,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_address file_chunk.address%TYPE,
		r_size file_chunk.size%TYPE,
		r_offset file_chunk."offset"%TYPE,
		r_hash file_chunk.hash%TYPE,
		r_revision file_revision.revision%TYPE
	)
	AS $$
DECLARE
	_r record;
BEGIN
	SELECT file_chunk.*, file_revision.revision
	INTO _r
	FROM life_data(_rootdir), file, file_chunk, file_revision
	WHERE
		file.rootdir_id = r_rootdir_id AND
		file.file = _file AND
		file_chunk.file_id = file.id AND
		file_chunk.chunk = _chunk AND
		file_revision.id = file_chunk.revision_id;

	IF _r IS NULL THEN
		r_error := concat('1:Chunk not found');
		return next;
		return;
	END IF;

	r_address := _r.address;
	r_size := _r.size;
	r_offset := _r.offset;
	r_hash := _r.hash;
	r_revision := _r.revision;
	return next;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION device_list(_username "user".username%TYPE,
	_device_id device.device%TYPE, _drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_last_auth_time device.last_time%TYPE,
		r_device_id device.device%TYPE
	) AS $$
DECLARE
	_row record;
BEGIN
	FOR _row IN SELECT *
		FROM "user", device
		WHERE "user".username = _username AND
			device.user_id = "user".id
	LOOP
		r_last_auth_time := _row.last_time;
		r_device_id := _row.device;
		return next;
	END LOOP;
	return;
END $$ LANGUAGE plpgsql;

-- получение списка чанков
CREATE OR REPLACE FUNCTION chunk_list(_rootdir UUID, _file UUID,
	_revision UUID,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE
	(
		r_chunk file_chunk.chunk%TYPE,
		r_hash file_chunk.hash%TYPE,
		r_offset file_chunk."offset"%TYPE,
		r_size file_chunk.size%TYPE,
		r_address file_chunk.address%TYPE
	) AS $$
DECLARE
	_row record;
BEGIN
	FOR _row IN
		SELECT file_chunk.* FROM rootdir, file, file_revision, file_chunk
		WHERE
			rootdir.rootdir = _rootdir AND
			file.rootdir_id = rootdir.id AND
			file.file = _file AND
			file.deleted = FALSE AND
			file_revision.file_id = file.id AND
			file_revision.revision = _revision AND
			file_chunk.revision_id = file_revision.id
	LOOP
		r_chunk = _row.chunk;
		r_hash = _row.hash;
		r_offset = _row.offset;
		r_size = _row.size;
		r_address = _row.address;
		return next;
	END LOOP;
	return;
END $$ LANGUAGE plpgsql;

-- получение списка ревизий
CREATE OR REPLACE FUNCTION revision_list(_rootdir UUID, _file UUID,
	_depth integer,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE
	(
		r_revision file_revision.revision%TYPE,
		r_parent_revision file_revision.revision%TYPE,
		r_chunks file_revision.chunks%TYPE,
		r_checkpoint event.checkpoint%TYPE
	) AS $$
DECLARE
	_row record;
BEGIN
	FOR _row IN
		SELECT * FROM (
			SELECT file_revision.revision AS parent_revision,
				a.revision AS revision,
				a.stored_chunks AS chunks,
				a.checkpoint AS checkpoint
			FROM
			(
				SELECT file_revision.*
				FROM life_data(_rootdir), file, file_revision
				WHERE
					file.rootdir_id = r_rootdir_id AND
					file.file = _file AND
					file.deleted = FALSE AND
					file_revision.file_id = file.id AND
					file_revision.fin = TRUE
				ORDER BY file_revision.checkpoint DESC LIMIT _depth
			) AS a
			LEFT JOIN file_revision ON file_revision.id = a.parent_id
		) AS s ORDER BY checkpoint ASC
	LOOP
		r_revision := _row.revision;
		r_parent_revision := _row.parent_revision;
		r_chunks := _row.chunks;
		r_checkpoint := _row.checkpoint;
		return next;
	END LOOP;
	return;
END $$ LANGUAGE plpgsql;

-- листинг состояния (список текущих файлов и директорий)
CREATE OR REPLACE FUNCTION state_list(_rootdir UUID,
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
		r_pubkey text,
		r_count integer
	) AS $$
DECLARE
	_ur record;
	_row record;
BEGIN
	SELECT INTO _ur
		r_user_id AS user_id,
		r_rootdir_id AS rootdir_id
	FROM life_data(_rootdir);
	FOR _row IN (
		SELECT * FROM (
			-- что бы получить последний чекпоинт файла
			-- нужно получить последнюю запись из file_meta
			-- и сравнить её с чекпоинтом из file_revision
			SELECT
				'file_revision' AS event_type,
				f.checkpoint,
				f.file,
				f.revision,
				f.directory,
				f.name,
				f.pubkey,
				f.count,
				file_revision.revision AS parent_revision
			FROM (
				SELECT
					GREATEST(COALESCE(file_meta.checkpoint, 0),
						file_revision.checkpoint) AS checkpoint,
					file.file AS file,
					file_revision.revision AS revision,
					directory.directory AS directory,
					file.filename AS name,
					file.pubkey AS pubkey,
					file_revision.chunks AS count,
					file_revision.parent_id AS parent_id
				FROM file, file_meta, file_revision, directory
				WHERE
					file.rootdir_id = _ur.rootdir_id AND
					file.deleted = FALSE AND
					file_meta.id =
						(SELECT MAX(id) FROM file_meta
						WHERE file_meta.file_id = file.id) AND
					file_revision.id =
						(SELECT MAX(id) FROM file_revision
						WHERE fin = TRUE AND file_revision.file_id = file.id) AND
					directory.id = file.directory_id
			) AS f
			LEFT JOIN file_revision ON file_revision.id = f.parent_id
			UNION SELECT
				'directory' AS event_type,
				directory_log.checkpoint AS checkpoint,
				NULL AS file,
				NULL AS revision,
				directory.directory AS directory,
				directory.path AS name,
				NULL AS pubkey,
				0 AS count,
				NULL AS parent_revision
			FROM directory, directory_log
			WHERE
				directory.rootdir_id = _ur.rootdir_id AND
				directory_log.id = directory.log_id
		) AS g ORDER BY checkpoint
	)
	LOOP
		r_type := _row.event_type;
		r_checkpoint := _row.checkpoint;
		r_rootdir := _rootdir;
		r_file := _row.file;
		r_revision := _row.revision;
		r_directory := _row.directory;
		r_parent_revision := _row.parent_revision;
		r_name := _row.name;
		r_pubkey := _row.pubkey;
		r_count := _row.count;
		return NEXT;
	END LOOP;
	return;
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
		r_pubkey text,
		r_count integer
	) AS $$
DECLARE
	_ur record;
	_row record;
	_xrow record;
BEGIN
	-- 1. текущее состояние, если указана рутдира и checkpoint = 0
	IF _checkpoint = 0 AND _rootdir IS NOT NULL THEN
		return QUERY SELECT * FROM state_list(_rootdir);
		return;
	END IF;
	-- получение базовой информации
	-- TODO: заменить говнище на life_data()
	BEGIN
		SELECT INTO _ur user_id, device_id FROM _life_, options
		WHERE options."key" = 'life_mark' AND
			_life_.mark = options.value_u;
	EXCEPTION WHEN undefined_table THEN -- nothing
	END;
	IF _ur IS NULL THEN
		RAISE EXCEPTION 'try to use begin_life() before call this';
	END IF;

	-- 2. листинг лога
	FOR _row IN
		SELECT * FROM event
		WHERE user_id = _ur.user_id AND
			checkpoint > _checkpoint AND
			hidden = FALSE AND
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
		WHEN 'file_revision'
		THEN
			SELECT INTO _xrow
				file.file AS file,
				file_revision.revision AS revision,
				directory.directory AS directory,
				--file_revision.parent_revision AS parent_revision,
				(SELECT revision FROM file_revision
					WHERE file_revision.id = parent_id) AS parent_revision,
				file.filename AS filename,
				file.pubkey AS pubkey,
				file_revision.chunks AS chunks
			FROM file, file_revision, directory
			WHERE
				file_revision.id = _row.target_id AND
				file.id = file_revision.file_id AND
				directory.id = file.directory_id;
			IF _xrow IS NULL THEN
				RAISE EXCEPTION 'zero result on file_revision, event %', _row.id;
				return;
			END IF;
			r_file := _xrow.file;
			r_revision := _xrow.revision;
			r_directory := _xrow.directory;
			r_parent_revision := _xrow.parent_revision;
			r_name := _xrow.filename;
			r_pubkey := _xrow.pubkey;
			r_count := _xrow.chunks;
		WHEN 'file_meta'
		THEN
			SELECT INTO _xrow *, directory.directory AS directory FROM
			(
				SELECT
					file.file AS file,
					file_revision.revision AS revision,
					(SELECT revision FROM file_revision
						WHERE file_revision.id = parent_id) AS parent_revision,
					file_meta.filename AS filename,
					file.pubkey AS pubkey,
					file_revision.chunks AS chunks,
					file_meta.directory_id AS directory_id
				FROM file, file_revision, file_meta
				WHERE
					file_meta.id = _row.target_id AND
					file_revision.id = file_meta.revision_id AND
					file.id = file_meta.file_id
			) AS e
			LEFT JOIN directory
			ON directory.id = e.directory_id;

			IF _xrow IS NULL THEN
				RAISE EXCEPTION 'zero result on file_meta, event %', _row.id;
				return;
			END IF;
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

-- проверка имени пользователя и возврат всякой секурной информации
CREATE OR REPLACE FUNCTION check_user(_username "user".username%TYPE,
	_secret "user".username%TYPE,
	_device_id device.device%TYPE,
	_drop_ _drop_ default 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_authorized boolean,
		r_registered timestamp with time zone,
		r_devices integer,
		r_last_device bigint,
		r_last_login text,
		r_last_addr text, /* не используется */
		r_next_server text
	) AS $$
DECLARE
	_user_id bigint;
	_row record;
	_devices integer;
BEGIN
	SELECT id
	INTO _user_id
	FROM "user"
	WHERE username = _username
		AND secret = _secret
	LIMIT 1;
	/* TODO: разнести check_user() и проверку устройства
	 по разным процедурам
	*/

	IF _user_id IS NOT NULL THEN
		/* получение последнего входа */
		SELECT * INTO _row
		FROM device
		WHERE device.user_id = _user_id
		ORDER BY id DESC
		LIMIT 1;

		/* вносим себя */
		WITH _xrow AS (
			UPDATE device
			SET last_time = now()
			WHERE user_id = _user_id AND device = _device_id
			RETURNING *
		) SELECT * INTO _row FROM _xrow;

		r_devices := (SELECT COUNT(*) FROM device WHERE user_id = _user_id);
		r_authorized := TRUE;

		IF _row IS NULL THEN
			INSERT 
			INTO device (user_id, device)
				SELECT _user_id, _device_id;
		END IF;

		/* выход */
		IF _row IS NOT NULL THEN
			r_registered := _row.reg_time;
			r_last_device := _row.device;
			r_last_login := _row.last_time;
			r_last_addr := '???';
		END IF;
		return next;
		return;
	END IF;
	r_authorized := FALSE;
	r_next_server := 'https://007:bond@as.swisstok.ru/swissconf/as3/session/';
	return next;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION chunk_info(_rootdir UUID,
	_file UUID, _chunk UUID,
	_drop_ _drop_ default 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_address text,
		r_driver text,
		r_size integer,
		r_offset integer
	) AS $$
DECLARE
	_r record;
BEGIN
	SELECT file_chunk.*
	INTO _r
	FROM
		life_data(_rootdir),
		file,
		file_chunk
	WHERE
		file.rootdir_id = r_rootdir_id AND
		file.file = _file AND
		file_chunk.file_id = file.id AND
		file_chunk.chunk = _chunk;

	IF _r IS NULL THEN
		r_error := concat('1:chunk "', _chunk,
			'" not found in (file, rootdir): ',
			'(', _rootdir, ', ', _file, ')');
		return next;
		return;
	END IF;

	r_address := _r.address;
	r_driver := _r.driver;
	r_size := _r.size;
	r_offset := _r.offset;
	return next;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION check_quota(_rootdir UUID,
	_drop_ _drop_ default 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_quota bigint,
		r_used bigint
	) AS $$
DECLARE
	_row RECORD;
BEGIN
	-- FIXME: слишком жирный запрос
	SELECT
		rootdir.quota AS quota,
		COALESCE(SUM(file_chunk.size), 0) AS used
	INTO _row
	FROM life_data(_rootdir)
	LEFT JOIN rootdir ON rootdir.id = r_rootdir_id
	LEFT JOIN file ON file.rootdir_id = rootdir.id
	LEFT JOIN file_chunk ON file_chunk.file_id IN (file.id)
	GROUP BY rootdir.id;

	if _row IS NULL THEN
		r_error := concat('1: rootdir information not exists (rootdir: "',
				_rootdir, '")');
		return next;
		return;
	END IF;

	r_quota := _row.quota;
	r_used := _row.used;
	return next;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION initial_user(_drop_ _drop_ default 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_mark text
	) AS $$
BEGIN
	SELECT value_u INTO r_mark FROM options WHERE key = 'life_mark';
	IF r_mark IS NULL THEN
		SELECT gen_random_uuid() INTO r_mark;
		INSERT INTO options ("key", value_u)
			VALUES ('life_mark', r_mark);
	END IF;
	return next;
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

-- file
CREATE TRIGGER tr_file_update AFTER UPDATE ON file
	FOR EACH ROW EXECUTE PROCEDURE file_update();

-- file_meta
CREATE TRIGGER tr_file_meta_action BEFORE INSERT ON file_meta
	FOR EACH ROW EXECUTE PROCEDURE file_meta_action();

CREATE TRIGGER tr_file_meta_delete AFTER DELETE ON file_meta
	FOR EACH ROW EXECUTE PROCEDURE file_delete();

-- event
CREATE TRIGGER tr_event_action BEFORE INSERT ON event
	FOR EACH ROW EXECUTE PROCEDURE event_action();

-- file_revision
CREATE TRIGGER tr_file_revision_update_action BEFORE UPDATE ON file_revision
	FOR EACH ROW EXECUTE PROCEDURE file_revision_update_action();

CREATE TRIGGER tr_file_revision AFTER DELETE ON file_revision
	FOR EACH ROW EXECUTE PROCEDURE file_delete();

-- directory
CREATE TRIGGER tr_directory_delete AFTER DELETE ON directory
	FOR EACH ROW EXECUTE PROCEDURE directory_delete();

-- ?
CREATE TRIGGER tr_file_chunk_action_after AFTER INSERT ON file_chunk
	FOR EACH ROW EXECUTE PROCEDURE file_chunk_action_after();


INSERT INTO options ("key", value_c, value_u)
	VALUES ('trash_dir', '.Trash', '00000000-0000-0000-0000-000000000000');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('incomplete_dir', '.Incomplete', 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('1_rootdir', 'First',
		'00000001-2003-5406-7008-900000000000');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('2_rootdir', 'Second',
		'11000001-2003-5406-7008-900000000000');
-- опция для костыля, что бы не возникло наложения данных из таблицы _life_ при обновлении бд
INSERT INTO options ("key", value_u)
	VALUES ('life_mark', gen_random_uuid());


-- Test

CREATE OR REPLACE FUNCTION t(stage integer DEFAULT 0,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE (r1 text, r2 bigint) AS $$
DECLARE
	_user_id bigint;
	_rootdir record;
	_dir record;
	_file record;
	_res record;
BEGIN
	IF 1 > stage THEN
		-- добавление нового пользователя
		INSERT INTO "user" (username, secret) VALUES ('bob', 'bob');
	END IF;

	SELECT INTO _user_id id FROM "user" WHERE username = 'bob';
	-- получение рутовой директории и создания подпапки
	SELECT INTO _rootdir rootdir AS guid, id
	FROM rootdir WHERE user_id = _user_id LIMIT 1;

	-- регистрируемся
	PERFORM begin_life('bob', 120);

	IF 2 > stage THEN
		-- создаём новую директорию
		PERFORM directory_create (_rootdir.guid, gen_random_uuid(), '/bla-bla');
	END IF;

	-- получении информации о директории
	-- (нужно искать по guid, но в тесте не имеет значения)
	SELECT INTO _dir directory AS guid, id
	FROM directory WHERE path = '/bla-bla';


	IF 3 > stage THEN
		-- сохраняем мету для файла
		SELECT INTO _file
			gen_random_uuid() AS guid,
			gen_random_uuid() AS revision_guid;

		RAISE NOTICE 'insert revision %, file %', _file.revision_guid, _file.guid;
		-- впихиваем файл почанково (два чанка)
		PERFORM insert_chunk(_rootdir.guid,
			_file.guid, _file.revision_guid, gen_random_uuid(),
			'hexhash', 1024, 0, 'host/none');
		PERFORM insert_chunk(_rootdir.guid,
			_file.guid, _file.revision_guid, gen_random_uuid(),
			'hexhash', 1024, 1024, 'host/none');

		-- закрываем ревизию
		SELECT INTO _res * FROM insert_revision(_rootdir.guid,
			_file.guid, _file.revision_guid,
			NULL, 'purpur.raw', '', _dir.guid, 2);

		r1 := _res.r_error;
		r2 := _res.r_checkpoint;
		return next;

		-- новая ревизия c parent_revision
		SELECT INTO _file
			_file.guid AS guid,
			_file.revision_guid AS parent_guid,
			gen_random_uuid() AS revision_guid;

		RAISE NOTICE 'insert revision %, file %', _file.revision_guid, _file.guid;
		PERFORM insert_chunk(_rootdir.guid,
			_file.guid, _file.revision_guid, gen_random_uuid(),
			'hexhash', 1024, 0, 'host/none');
		PERFORM insert_chunk(_rootdir.guid,
			_file.guid, _file.revision_guid, gen_random_uuid(),
			'hexhash', 1024, 1024, 'host/none');

		SELECT INTO _res * FROM insert_revision(_rootdir.guid,
			_file.guid, _file.revision_guid,
			_file.parent_guid, 'purpur.raw', '', _dir.guid, 2);

		r1 := _res.r_error;
		r2 := _res.r_checkpoint;
		return next;
	END IF;

	-- смена устройства
	PERFORM begin_life('bob', 121);


	r1 := NULL;
	r2 := NULL;
	return;
END $$ LANGUAGE plpgsql;

