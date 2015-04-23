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

DROP TABLE IF EXISTS rootdir_log CASCADE;
DROP TABLE IF EXISTS file_chunk CASCADE;
DROP TABLE IF EXISTS file_revision CASCADE;
DROP TABLE IF EXISTS options CASCADE;
DROP TABLE IF EXISTS file CASCADE;
DROP TABLE IF EXISTS directory CASCADE;
DROP TABLE IF EXISTS directory_log CASCADE;
DROP TABLE IF EXISTS event CASCADE;
DROP TABLE IF EXISTS rootdir CASCADE;
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
	user_id bigint REFERENCES "user"(id),
	
	-- для удобства вставки в лог и получение чекпоинта
	checkpoint bigint NOT NULL,
	rootdir_id bigint NOT NULL,

	rootdir_guid UUID NOT NULL DEFAULT gen_random_uuid(),
	-- если NULL, то директория удаляется
	title varchar(1024) DEFAULT NULL
);

CREATE SEQUENCE rootdir_seq;
-- текущее состояние рутдир
CREATE TABLE IF NOT EXISTS rootdir
(
	id bigint NOT NULL DEFAULT nextval('rootdir_seq') PRIMARY KEY,
	checkpoint bigint NOT NULL DEFAULT trunc(extract(epoch from now())),
	user_id bigint REFERENCES "user"(id),
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
	rootdir_id bigint REFERENCES rootdir(id),
	
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
	id bigint DEFAULT nextval('directory_seq') PRIMARY KEY,
	
	rootdir_id bigint NOT NULL REFERENCES rootdir(id),

	directory_guid UUID NOT NULL,
	path varchar(4096) DEFAULT NULL,

	-- информацию по времени создания и чекпоинт можно получить из directory_log
	log_id bigint REFERENCES directory_log(id),

	UNIQUE(rootdir_id, directory_guid)
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
	dir_id bigint REFERENCES directory(id)
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

CREATE OR REPLACE FUNCTION directory_log_action()
	RETURNS TRIGGER AS $$
DECLARE
	_row record;
	_null record;
	_message text;
	_stack text;
	_event_id bigint;
BEGIN
	-- теперь нужно получить checkpoint
	WITH _row AS (
		INSERT INTO event (rootdir_guid, "type", target_id)
		VALUES ((SELECT rootdir_guid FROM rootdir WHERE id = new.rootdir_id),
			'directory', new.id)
		RETURNING *
	) SELECT * FROM _row INTO _null;
	new.checkpoint = _null.checkpoint;
	_event_id = _null.id;
	
	IF NEW.path IS NULL THEN
		raise exception 'directory destroy not implement (user: %, rootdir: %)',
			(SELECT username FROM "user" WHERE id = new.user_id),
			new.directory_guid;
		return new;
	ELSE
		-- требуется указавать directory_id или directory_guid
		-- или оба вместе
		IF new.directory_id IS NULL AND new.directory_guid IS NULL THEN
			RAISE EXCEPTION 'directory update has both no directory_id and directory_guid';
			return new;
		END IF;

		-- исправление пути, если пришло херня
		IF substring(NEW.path from 1 for 1) != '/' THEN
			NEW.path = concat('/', NEW.path);
		END IF;
		RAISE NOTICE 'dir: guid: %, id: %', new.directory_guid, new.directory_id;
		-- нужно получить directory_id
		-- если директория присутсвует, то нужно обновить параметры
		WITH _row AS (
			UPDATE directory SET path = new.path, log_id = new.id
			WHERE 
				rootdir_id = new.rootdir_id
				AND (new.directory_id IS NOT NULL AND id = new.directory_id
						OR (new.directory_id IS NULL AND TRUE))
				AND (new.directory_guid IS NOT NULL
					AND directory_guid = new.directory_guid
						OR (new.directory_guid IS NULL AND TRUE))
			RETURNING *
		) SELECT * FROM _row INTO _null;

		-- директория отсутвует, нужно создать новую
		IF _null IS NULL THEN
			-- FIXME: если new.directory_id не пустой
			-- и UPDATE ничего не вернул, то пришло какое-то говно
			-- нужно сообщить или исправить
			WITH _row AS (
				INSERT INTO directory(rootdir_id, directory_guid, path, log_id)
					VALUES(new.rootdir_id, new.directory_guid, new.path, new.id)
				RETURNING *
			) SELECT * FROM _row INTO _null;
		END IF;
	END IF;

	-- ошибочка
	IF _null IS NULL THEN

		raise exception 'directory(% "%" id: %, user: %) update failed',
			new.directory_guid, new.path, new.directory_id,
			(SELECT username FROM "user" WHERE id = new.user_id);
		return new;
	END IF;

	-- на всякий случай проверяем незаполненные поля
	IF new.directory_id IS NULL AND _null.id IS NOT NULL THEN
		new.directory_id = _null.id;
	END IF;
	IF new.directory_guid IS NULL AND _null.directory_guid IS NOT NULL THEN
		new.directory_guid = _null.directory_guid;
	END IF;

	-- а теперь костыль: нужно обновить поля в directory_log
	-- если бы триггер был не AFTER, а BEFORE, то выполнять это не было бы необходимости
	-- но из-за log_id REFERENCES придётся выкручиваться
	UPDATE directory_log
	SET
		directory_id = new.directory_id,
		directory_guid = new.directory_guid,
		checkpoint = new.checkpoint,
		path = new.path
	WHERE id = new.id;

	RETURN NEW;
EXCEPTION WHEN OTHERS THEN
	GET STACKED DIAGNOSTICS _message = MESSAGE_TEXT;
	GET STACKED DIAGNOSTICS _stack = PG_EXCEPTION_CONTEXT;
	raise exception E'event_id = %, %\n%', _event_id, _message, _stack;
END $$ LANGUAGE plpgsql;

/*
	при создании пользователя заполняет таблицу базовыми значениями
*/
CREATE OR REPLACE FUNCTION user_action()
	RETURNS trigger AS $$
DECLARE
BEGIN
	INSERT INTO rootdir_log (user_id, title) VALUES (new.id, 'First');
	return new;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rootdir_action_insert()
	RETURNS trigger AS $$
DECLARE
	_row record;
BEGIN
	-- впихнуть стандартные директории в рутдиру
	FOR _row IN SELECT value_c, value_u FROM options WHERE "key" LIKE '%_dir' LOOP
		INSERT INTO directory_log(rootdir_id, directory_guid, path)
		VALUES(new.id, _row.value_u, _row.value_c);
	END LOOP;
	return new;
END $$ LANGUAGE plpgsql;

-- обработчик добавления в rootdir_log
CREATE OR REPLACE FUNCTION rootdir_log_action()
	RETURNS trigger AS $$
DECLARE
	_row record;
	_null record;
	_checkpoint bigint;
	_event_id bigint;
	_message text;
	_stack text;
BEGIN
	-- в логе событий нужно отметиться в самом начале
	-- если в ходе заполнения произошла ошибка -- запись требуется удалить
	with _row AS (
		INSERT INTO event (rootdir_guid, "type", target_id)
		VALUES (new.rootdir_guid, 'rootdir', new.id)
		RETURNING *
	) SELECT * INTO _null FROM _row;
	new.checkpoint = _null.checkpoint;
	_event_id = _null.id;

	if new.title IS NOT NULL then
		-- можно проверить на NULL new.rootdir_id и new.rootdir_guid
		-- но пока проще сделать попытку апдейта
		WITH _row AS (
			UPDATE rootdir SET title = new.title
			WHERE
				user_id = new.user_id
				AND (new.rootdir_id IS NULL AND rootdir_guid = new.rootdir_guid
					OR (new.rootdir_id IS NOT NULL AND id = new.rootdir_id))
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
		RAISE EXCEPTION 'rootdir destroy not implement (user: %, rootdir: %)',
			(SELECT username FROM "user" WHERE id = new.user_id), new.rootdir_guid;
	end if;
	if _null IS NULL then
		RAISE EXCEPTION 'rootdir(% "%") update failed', new.rootdir_guid, new.title;
		return new;
	end if;

	new.rootdir_id = _null.id;

	return new;
EXCEPTION WHEN OTHERS THEN
	GET STACKED DIAGNOSTICS _message = MESSAGE_TEXT;
	GET STACKED DIAGNOSTICS _stack = PG_EXCEPTION_CONTEXT;
	raise exception E'event_id = %, %\n%', _event_id, _message, _stack;
	-- вообще, вся транзация не выполнится, если в процедуре произойдёт ошибка,
	-- потому удалять что-либо бессмысленно
	--IF _event_id IS NOT NULL THEN
	--	DELETE FROM event WHERE id = _event_id;
	--END IF;
END $$ LANGUAGE plpgsql;

-- вешанье триггеров, инжекция базовых значений
CREATE TRIGGER tr_directory_log_action AFTER INSERT ON directory_log
	FOR EACH ROW EXECUTE PROCEDURE directory_log_action();

CREATE TRIGGER tr_user_action AFTER INSERT ON "user"
	FOR EACH ROW EXECUTE PROCEDURE user_action();

CREATE TRIGGER tr_rootdir_log_action BEFORE INSERT ON rootdir_log
	FOR EACH ROW EXECUTE PROCEDURE rootdir_log_action();

CREATE TRIGGER tr_rootdir_action_insert AFTER INSERT ON rootdir
	FOR EACH ROW EXECUTE PROCEDURE rootdir_action_insert();

INSERT INTO options ("key", value_c, value_u)
	VALUES ('trash_dir', '.Trash', '10000002-3004-5006-7008-900000000000');
INSERT INTO options ("key", value_c, value_u)
	VALUES ('incomplete_dir', '.Incomplete',
		'20000002-3004-5006-7008-900000000000');

