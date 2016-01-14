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
BEGIN
	/* версия структуры */
	SELECT INTO _struct_version_value '9';

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
DROP TABLE IF EXISTS file_chunk_prepare CASCADE;
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
DROP SEQUENCE IF EXISTS file_chunk_prepare_seq CASCADE;

DROP TYPE IF EXISTS event_type CASCADE;

CREATE SEQUENCE user_seq;
CREATE TABLE IF NOT EXISTS "user"
(
	id bigint NOT NULL DEFAULT nextval('user_seq') PRIMARY KEY,
	created timestamp with time zone NOT NULL DEFAULT now(),
	username varchar(1024) NOT NULL CHECK(char_length(username) > 0),
	secret varchar(96) NOT NULL,
	store bytea NOT NULL DEFAULT E'',
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
	store bytea NOT NULL DEFAULT E'',
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
	_r integer;
BEGIN
	SELECT COUNT(*)
	INTO _r
	FROM directory, options
	WHERE
		options."key" = 'trash_dir' AND
		directory.rootdir_id = _rootdir_id AND
		directory.directory = options.value_u AND
		directory.id = _directory_id;

	-- FIXME: record IS NULL is abscess
	IF _r != 0 THEN
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

-- таблица для хранения предварительных записей о чанках
-- для неё требуется
-- уникальный набор chunk_hash, chunk_size и rootdir_id
CREATE SEQUENCE file_chunk_prepare_seq;
CREATE TABLE IF NOT EXISTS file_chunk_prepare
(
	id bigint DEFAULT nextval('file_chunk_prepare_seq') PRIMARY KEY,

	hash character varying(256) NOT NULL,
	size integer NOT NULL,

	rootdir_id bigint NOT NULL REFERENCES rootdir(id),
	location_group bigint NOT NULL DEFAULT nextval('file_chunk_group_seq'),

	UNIQUE(rootdir_id, size, hash)
);

-- Базовые значения

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

