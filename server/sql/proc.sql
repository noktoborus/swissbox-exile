/* vim: syntax=pgsql
 */
/* процедурки */

/*
 	процедуры для сборки файла:
	link_chunk()
	insert_chunk()
	insert_revision()

*/


-- костыль для гроханья всех хранимых процедур
DROP TYPE IF EXISTS _drop_ CASCADE;
CREATE TYPE _drop_ AS ENUM ('drop');

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

CREATE OR REPLACE FUNCTION _revision_is_complete(
	_revision_id file_revision.id%TYPE, _drop_ _drop_ DEFAULT 'drop')
	RETURNS boolean AS $$
DECLARE
	_r record;
	maxsize bigint DEFAULT NULL;
	chunks integer DEFAULT NULL;
	e_size bigint DEFAULT 0;
BEGIN
	SELECT e.chunks
	INTO chunks
	FROM (
		SELECT 
			CASE
				WHEN file_revision.chunks = 0
					THEN COALESCE(file_temp.chunks, 0)
				ELSE file_revision.chunks END AS chunks,
			file_revision.stored_chunks AS stored
		FROM file_revision
		/*
		нужных данных в file_revision может не оказаться,
		но они могут быть в file_temp
		*/
		LEFT JOIN file_temp
		ON
			file_temp.id = _revision_id
		WHERE
			file_revision.id = _revision_id
		) AS e
	WHERE e.chunks = e.stored;
	
	IF chunks IS NULL THEN
		return FALSE;
	ELSIF chunks = 0 THEN
		/*
		если количество чанков == 0, то мы в любом случае
		считаем что ревизия собралась
		-- FIXME: что делать, если stored != chunks?
		*/
		return TRUE;
	END IF;
	/* т.к. у нас нет общего размера файла
		то готовность вычисляем по
		MAX(offset) + size
		при stored_chunks = chunks
	*/
	SELECT MAX(file_chunk."offset" + file_chunk.size)
	INTO maxsize
	FROM file_chunk
	WHERE file_chunk.revision_id = _revision_id;

	IF maxsize IS NULL THEN
		return false;
	END IF;

	-- ищим дырки
	FOR _r IN
		SELECT "offset", size
		FROM file_chunk
		WHERE file_chunk.revision_id = _revision_id
		ORDER BY "offset" ASC LOOP
		
		IF _r."offset" > e_size THEN
			-- дырка!
			return false;
		ELSIF _r."offset" < e_size THEN
			-- наложение
			IF _r."offset" + _r."size" > e_size THEN
				e_size := e_size + _r.size;
			END IF;
		ELSE
			e_size := e_size + _r.size;
		END IF;
	END LOOP;

	return (e_size = maxsize);
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
	returns table(r_error text, r_checkpoint bigint, r_complete boolean) as $$
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
		file_revision.checkpoint AS checkpoint,
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

	-- здесь нужно или проверять _ur.permit или убрать из таблиц поле "fin"
	IF NOT _ur.revision_id IS NULL AND NOT _ur.checkpoint IS NULL THEN
		r_error := concat('3:file revision already completed ',
			'(rootdir "', _rootdir_guid, '", ',
			'file "', _file_guid, '", ',
			'revision "', _revision_guid, '")');
		r_complete := TRUE;
		r_checkpoint := _ur.checkpoint;
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
	SELECT id, revision
	INTO _parent
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

	-- prepare выполняется только для _chunks > 0
	IF _prepare = TRUE AND _chunks > 0 THEN
		RAISE NOTICE 'prepare ';
		INSERT INTO file_temp SELECT
			_ur.revision_id,
			_dir_guid,
			_ur.directory_id,
			_filename,
			_pubkey,
			_chunks;
		/* после внесения временных данных можно сделать проверку на готовность
			(процедура _revision_is_complete работает с таблицей "file_temp")

		*/
		r_complete := _revision_is_complete(_ur.revision_id);
		IF NOT r_complete THEN
			-- если ревизия не готова, смысла дальше выполнять код нет
			return next;
			return;
		END IF;
	ELSE
		/* выборка временных данных */
		SELECT * INTO _row
		FROM file_temp
		WHERE id = _ur.revision_id;

		IF _row IS NOT NULL THEN
			_dir_guid := COALESCE(_row.directory, _dir_guid);
			_filename := COALESCE(_row.filename, _filename);
			_pubkey := COALESCE(_row.pubkey, _pubkey);
			_chunks := COALESCE(_row.chunks, _chunks);
		END IF;

		/* если это не подготовка (prepare), то нужно обязательно
		 проверить готовность
		*/
		r_complete := _revision_is_complete(_ur.revision_id);
	END IF;

	-- 2. проверка на собранность файла
	IF NOT r_complete THEN
		r_error := concat('1:file not completed ',
			'(rootdir "', _rootdir_guid, '", ',
			'file "', _file_guid, '", ',
			'revision "', _revision_guid, '")');
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
	DELETE FROM file_temp WHERE id = _ur.revision_id;

	r_complete := _revision_is_complete(_ur.revision_id);
	return next;
END $$ LANGUAGE plpgsql;

-- внесение нового чанка в таблицу (с упреждающей записью информации о файле и ревизии)
CREATE OR REPLACE FUNCTION insert_chunk(
	_rootdir_guid UUID, _file_guid UUID, _revision_guid UUID, _chunk_guid UUID,
	_chunk_hash varchar(1024), _chunk_size integer, _chunk_offset integer,
	_address text, _drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_complete boolean
	) AS $$
DECLARE
	_row record;
	-- user_id and rootdir_id
	_ur record;

	_dir_id bigint;
	_file_id bigint;
	_revision_id bigint;
	_location_group bigint;
BEGIN
	-- 1. получение базовой информации
	SELECT
		r_rootdir_id AS r,
		r_user_id AS u
	INTO _ur
	FROM life_data(_rootdir_guid);

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
	-- если revision_id не нашёлся, то нужно вставить новую ревизию
	IF _revision_id IS NULL THEN
		WITH _row AS (
			INSERT INTO file_revision (file_id, revision, chunks)
			VALUES (_file_id, _revision_guid, 0)
			RETURNING *
		) SELECT id INTO _revision_id FROM _row;
	END IF;

	-- 4. подбор location_group

	-- выборка location_group из _prepare (если есть)
	with _xrow AS (
		DELETE FROM file_chunk_prepare
		WHERE rootdir_id = _ur.r AND
			size = _chunk_size AND
			hash = _chunk_hash
		RETURNING *
	) SELECT location_group INTO _location_group FROM _xrow LIMIT 1;

	-- если нет, то пытаемся найти подобное в списке чанков
	IF _location_group IS NULL THEN
		SELECT location_group
		INTO _location_group
		FROM file_chunk
		WHERE file_chunk.hash = _chunk_hash AND
			file_chunk.size = _chunk_size AND
			file_chunk.rootdir_id = _ur.r;
	END IF;

	-- если совсем нет, то генерируем свой
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

	-- проверка на готовность
	r_complete := _revision_is_complete(_revision_id);

	return next;
	return;
END $$ LANGUAGE plpgsql;

-- линковка чанка из старой ревизии с новой ревизией
CREATE OR REPLACE FUNCTION link_chunk(
	_rootdir_guid UUID, _file_guid UUID, _chunk_guid UUID,
	_new_chunk_guid UUID, _new_revision_guid UUID,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_complete boolean
	) AS $$
DECLARE
	_user_id "user".id%TYPE;
	_row record;
	_xrow record;
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
		r_error := concat('file "', _file_guid,
			'" not found in rootdir "',
		_rootdir_guid, '", file "', _file_guid, '"');
		return next;
		return;
	END IF;
	SELECT *
	INTO _xrow
	FROM insert_chunk(_row.rootdir, _row.file, _row.revision,
		_row.chunk, _row.hash, _row.size, _row.offset, _row.address);

	r_error := _xrow.r_error;
	r_complete := _xrow.r_complete;
	return next;
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

	-- причёсывание пути, если вдруг прислали ошмёток (как?)
	IF substring(_dirname from 1 for 1) != '/' THEN
		_dirname = concat('/', _dirname);
	END IF;

	IF _dirname IS NULL THEN
		-- проверяем что не хотят удалить системную директорию
		-- переименовывать можно, удалять нельзя
		IF (SELECT COUNT(*)
				FROM options
				WHERE
					"key" LIKE '%\_dir' AND
					value_u = _directory) != 0 THEN
			r_error := '1:system directory guard dissatisfied';
			return next;
			return;
		END IF;
	END IF;

	-- проверка последней операции над директорией
	WITH _row AS (
		SELECT path, checkpoint FROM (
			SELECT path, checkpoint FROM directory_log
			WHERE rootdir_id = _ur.rootdir_id AND
				directory = _directory
			ORDER BY checkpoint DESC
			LIMIT 1
		) AS sub1
		WHERE
			(_dirname IS NULL AND path IS NULL) OR
				(_dirname IS NOT NULL AND path IS NOT NULL AND _dirname = path)
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

-- TODO: удалить к хуям, в следствии того, что file_temp.id на самом деле не file.id, а file_revision.id происходит какая-то херня
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
	t record;
BEGIN

	-- выборка файла
	SELECT
		file.id AS file_id,
		r_rootdir_id AS rootdir_id,
		file.file AS file_guid,
		file.filename AS filename,
		file.directory_id AS directory_id,
		file.pubkey AS pubkey
	INTO t
	FROM life_data(_rootdir), file
	WHERE
		file.rootdir_id = r_rootdir_id AND
		file.file = _file;

	-- выборка ревизии
	-- если указана конкретная ревизиая, то выдаём её,
	-- иначе выдаём последнюю
	SELECT
		file_revision.revision AS revision_guid,
		file_revision.chunks AS chunks,
		file_revision.stored_chunks AS stored_chunks,
		parent_revision.revision AS parent_guid,
		file_revision.id AS rev_id
	INTO _rev
	FROM file_revision
	LEFT JOIN file_revision AS parent_revision
	ON parent_revision.id = file_revision.parent_id
	WHERE
		file_revision.file_id = t.file_id AND
		CASE
			WHEN _revision IS NOT NULL
				THEN file_revision.revision = _revision
			ELSE
				TRUE
		END AND
		file_revision.fin = NOT COALESCE(uncompleted, False)
	ORDER BY file_revision.checkpoint DESC LIMIT 1;
	
	-- выборка файла и директории
	SELECT
		t.file_id,
		t.rootdir_id,
		t.file_guid,
		COALESCE(file_temp.directory, directory.directory) AS directory_guid,
		COALESCE(file_temp.filename, t.filename) AS filename,
		COALESCE(file_temp.pubkey, t.pubkey) AS pubkey
	INTO _r
	FROM (SELECT 1 WHERE NOT t IS NULL) AS x -- костыль
	LEFT JOIN file_temp ON file_temp.id = _rev.rev_id
	LEFT JOIN directory ON directory.id = t.directory_id;

	IF _r IS NULL THEN
		r_error := concat('1:file "', _file, '" in rootdir "', _rootdir, '" ',
			'not found');
		return next;
		return;
	END IF;

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

-- возвращает ошибку, если чанк уже есть
-- возвращает номер группы, если прошло успешно
CREATE OR REPLACE FUNCTION chunk_prepare(
	_rootdir rootdir.rootdir%TYPE,
	_chunk_hash file_chunk.hash%TYPE,
	_chunk_size file_chunk.size%TYPE,
	_drop_ _drop_ DEFAULT 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_address file_chunk.address%TYPE,
		r_driver file_chunk.driver%TYPE,
		r_location_group file_chunk.location_group%TYPE
	)
	AS $$
DECLARE
	_r record;
	_e record;
	_n file_chunk.location_group%TYPE;
BEGIN
	SELECT
		r_rootdir_id
	INTO _r
	FROM life_data(_rootdir);


	-- поиск чанка в начале
	SELECT address, driver, location_group
	INTO _e
	FROM file_chunk
	WHERE rootdir_id = _r.r_rootdir_id AND
				size = _chunk_size AND
				hash = _chunk_hash
	LIMIT 1;

	IF NOT _e IS NULL THEN
		r_address := _e.address;
		r_driver := _e.driver;
		r_location_group := _e.location_group;
		return next;
		return;
	END IF;

	-- если запись присутсвует, то это не должно вызвать ошибку
	-- ошибка прийдёт после того, как кто-то захочет финализировать
	-- запись (например, если запись велась с разных серверов)

	SELECT location_group
	INTO _n
	FROM file_chunk_prepare
	WHERE rootdir_id = _r.r_rootdir_id AND
		size = _chunk_size AND
		hash = _chunk_hash LIMIT 1;

	IF _n IS NULL THEN
		with _ro AS (
			INSERT
			INTO file_chunk_prepare (hash, size, rootdir_id) 
			VALUES (_chunk_hash, _chunk_size, _r.r_rootdir_id)
			RETURNING location_group
		) SELECT _ro.location_group AS lc_group INTO _n FROM _ro;
	END IF;

	IF _n IS NULL THEN
		r_error := '1:unknown error';
		return next;
		return;
	END IF;

	r_location_group = _n;
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

	SELECT INTO _ur
		r_user_id AS user_id,
		r_device_id AS device_id
	FROM life_data();

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
			-- FIXME: record IS NULL is abscess
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

			-- FIXME: record IS NULL is abscess
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

		-- FIXME: record IS NULL is abscess
		IF _row IS NULL THEN
			INSERT 
			INTO device (user_id, device)
				SELECT _user_id, _device_id;
		END IF;

		/* выход */
		-- FIXME: record IS NULL is abscess
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
		r_offset integer,
		r_group integer
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

	-- FIXME: record IS NULL is abscess
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
	r_group := _r.location_group;
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

CREATE OR REPLACE FUNCTION store_save(
	_store bytea, _share boolean, _offset integer, _length integer,
	_drop_ _drop_ default 'drop')
	RETURNS TABLE
	(
		r_error text
	) AS $$
DECLARE
	_r record;
BEGIN
	IF _offset = 0 AND _length != 0 THEN
		_offset = 1;
	END IF;
	SELECT INTO _r	*
	FROM life_data();

	IF NOT _share THEN
		IF _offset THEN
			UPDATE device
			SET store = overlay(store placing _store from _offset for _length)
			WHERE device.id = _r.r_device_id;
		ELSE
			UPDATE device
			SET store = _store
			WHERE device.id = _r.r_device_id;
		END IF;
	ELSE
		IF _offset THEN
			UPDATE "user"
			SET store = overlay(store placing _store from _offset for _length)
			WHERE "user".id = _r.r_user_id;
		ELSE
			UPDATE "user"
			SET store = _store
			WHERE "user".id = _r.r_user_id;
		END IF;
	END IF;

	return next;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION store_load(
	_share boolean, _offset integer, _length integer,
	_drop_ _drop_ default 'drop')
	RETURNS TABLE
	(
		r_error text,
		r_store bytea,
		r_length integer
	) AS $$
DECLARE
	_r record;
BEGIN
	IF NOT _share THEN
		IF _length THEN
			SELECT
			INTO _r
				substring(store from _offset for _length) AS x_store,
				octet_length(store) AS x_length
			FROM device, life_data()
			WHERE device.id = r_device_id;
		ELSE
			SELECT
			INTO _r
				substring(store from _offset) AS x_store,
				octet_length(store) AS x_length
			FROM device, life_data()
			WHERE device.id = r_device_id;
		END IF;
	ELSE
		IF _length THEN
			SELECT
			INTO _r
				substring(store from _offset for _length) AS x_store,
				octet_length(store) AS x_length
			FROM "user", life_data()
			WHERE "user".id = r_user_id;
		ELSE
			SELECT
			INTO _r
				substring(store from _offset) AS x_store,
				octet_length(store) AS x_length
			FROM "user", life_data()
			WHERE "user".id = r_user_id;
		END IF;
	END IF;

	r_length := _r.x_length;
	r_store := _r.x_store;
	return next;
END $$ LANGUAGE plpgsql;

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

