/* vim: syntax=pgsql
 */
/* триггера */
 
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

	-- FIXME: record IS NULL is abscess
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
	_old_path text;
	_trash_id bigint;
	i integer;
	_rootdir_info record;
BEGIN
	-- предпологается что в new.path уже нормализованный путь
	-- (см. directory_log.path)

	IF new.fin = TRUE THEN
		-- если финализация, то дальнейшая обработка не нужна
		-- FIXME: костыль
		return new;
	END IF;

	-- получение информации по rootdir
	SELECT user_id, rootdir
	INTO _rootdir_info
	FROM rootdir
	WHERE rootdir.id = new.rootdir_id;

	-- удаление происходит в несколько стадий:
	-- 1. пометка всех файлов как "deleted" и перенос их в .Trash
	-- 2. удаление самой директории
	IF new.path IS NULL THEN
		-- получение id треша
		SELECT directory.id FROM options, directory
		INTO _trash_id
		WHERE
			options."key" = 'trash_dir' AND
			directory.rootdir_id = new.rootdir_id AND
			directory.directory = options.value_u;

		-- т.к. path IS NULL, то нужно выбрать последнее имя директории из бд
		-- path нужен для удаления всех поддиректорий
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

		-- получение чекпоинта
		WITH _row AS (
			INSERT INTO event (user_id, rootdir, "type", target_id)
				SELECT
					_rootdir_info.user_id,
					_rootdir_info.rootdir,
					'directory' AS "type",
					new.id AS target_id
			RETURNING *
		) SELECT checkpoint FROM _row INTO new.checkpoint;

		-- обновление файлов в самой директории
		UPDATE file
		SET directory_id = _trash_id,
			deleted = TRUE
		WHERE
			rootdir_id = new.rootdir_id AND
			file.directory_id = new.directory_id;

		-- обход списка поддиректорий, пометка как удалённых
		-- и создание спрятанного евента для checkpoint
		FOR _row IN
			SELECT id, directory FROM directory
			WHERE rootdir_id = new.rootdir_id AND
			directory.path LIKE new.path || '%' AND
			directory.id != new.directory_id
			ORDER BY id ASC
		LOOP
			-- перемещение всех файлов в треш
			UPDATE file
			SET directory_id = _trash_id,
				deleted = TRUE
			WHERE
				rootdir_id = new.rootdir_id AND
				file.directory_id = _row.id;
			-- удаление директории происходит в directory_log_action_after()
			-- здесь требуется только внести запись
			INSERT
			INTO directory_log
				(rootdir_id, parent_checkpoint, directory_id, directory, fin)
			VALUES
				(
					new.rootdir_id,
					new.checkpoint,
					_row.id,
					_row.directory,
					-- не позволяем дополнительно обрабатывать
					-- удаляемую директорию
					TRUE
				);
		END LOOP;

		new.path := NULL;
		new.fin := TRUE;
	ELSE
		-- переименование или создание директории
		SELECT NULL INTO _row;

		-- отметка о изменении директории
		WITH _row AS (
			INSERT INTO event (user_id, rootdir, "type", target_id)
				SELECT
					_rootdir_info.user_id,
					_rootdir_info.rootdir,
					'directory' AS "type",
					new.id AS target_id
			RETURNING *
		) SELECT checkpoint FROM _row INTO new.checkpoint;

		-- проверка наличия директории
		-- такой жуткий кейс связан с тем, что триггеры могут быть
		-- вызваны руками с неполным набором информации
		-- (только directory_id или UUID)
		CASE
		WHEN new.directory_id IS NOT NULL THEN
			SELECT * INTO _row FROM directory
			WHERE rootdir_id = new.rootdir_id AND id = new.directory_id;
		WHEN new.directory IS NOT NULL THEN
			SELECT * INTO _row FROM directory
			WHERE rootdir_id = new.rootdir_id AND directory = new.directory;
		END CASE;

		IF _row IS NOT NULL THEN
			-- переименование
			-- назначаем обе переменные
			-- ибо лень вычислять каких данных у нас не хватает
			new.directory_id = _row.id;
			new.directory = _row.directory;
			_old_path = _row.path;
			-- переименование всех поддиректорий
			FOR _row IN
				SELECT
					id,
					directory,
					new.path
						|| substring(path from char_length(_old_path) + 1)
						AS path
				FROM directory
				WHERE rootdir_id = new.rootdir_id AND
				directory.path LIKE new.path || '%' AND
				directory.id != new.directory_id
				ORDER BY id ASC
			LOOP
				INSERT
				INTO directory_log
					(
						rootdir_id,
						parent_checkpoint,
						directory_id,
						directory,
						fin,
						path
					)
				VALUES
					(
						new.rootdir_id,
						new.checkpoint,
						_row.id,
						_row.directory,
						TRUE,
						_row.path
					);
			END LOOP;
		ELSE
			-- если директория не найдена, то это создание
			new.directory_id = nextval('directory_seq');
		END IF;



	END IF;

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
		
	ELSE
		-- обновление таблицы "directory"
		-- UPDATE OR INSERT
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
	END IF;

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


