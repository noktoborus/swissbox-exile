/* vim: syntax=pgsql
 */
/* тестики */

-- Test
CREATE OR REPLACE FUNCTION bug_DDB419(_drop_ _drop_ DEFAULT 'drop')
	RETURNS void AS $$
DECLARE
	r record;
	rootdir uuid DEFAULT '00000001-2003-5406-7008-900000000000'::UUID;
	dir1 uuid DEFAULT '6212c1a4-9551-47a6-9bbe-4e07cc60633a'::UUID;
	dir2 uuid DEFAULT '1b8c0d06-0817-4964-a99c-364004ba51b4'::UUID;
	dir3 uuid DEFAULT '7ca70a0f-0345-407c-b2b6-fdf64b2ad62a'::UUID;
BEGIN
	INSERT INTO "user" (username, secret) VALUES ('ddb419', 'ddb419');
	PERFORM begin_life('ddb419', 419);

	/* создание /dir4 */
	SELECT * INTO r FROM directory_create(rootdir, dir1, 'dir4');
	RAISE NOTICE 'directory_create(dir1): %', r;

	/* создание /dir5 */
	SELECT * INTO r FROM directory_create(rootdir, dir2, 'dir5');
	RAISE NOTICE 'directory_create(dir2): %', r;

	/* создание /dir2_rename */
	SELECT * INTO r FROM directory_create(rootdir, dir3, 'dir2_rename');
	RAISE NOTICE 'directory_create(dir3): %', r;

	/* перемещение /dir5 в /dir4 */
	SELECT * INTO r FROM directory_create(rootdir, dir2, 'dir4/dir5');
	RAISE NOTICE 'directory_create(dir2): %', r;

	/* перемещение /dir4/dir5 в /dir2_rename/dir4 */
	SELECT * INTO r FROM directory_create(rootdir, dir2, 'dir2_rename/dir4/dir5');
	RAISE NOTICE 'directory_create(dir2): %', r;

	/* перемещение /dir4 в /dir2_rename */
	SELECT * INTO r FROM directory_create(rootdir, dir1, 'dir2_rename/dir4');
	RAISE NOTICE 'directory_create(dir1): %', r;

	/* проверка на корректность, проверка покрывает не все результаты,
	  но хрен с ними
	*/
	SELECT
		string_agg(r_name, ', ') AS r1,
		COUNT(*) AS c1
	INTO r
	FROM log_list(rootdir, 0)
	WHERE r_directory IN (dir1, dir2, dir3) AND
		r_name NOT IN ('/dir2_rename/', '/dir2_rename/dir4/', '/dir2_rename/dir4/dir5/');
	IF r.c1 != 0 THEN
		RAISE EXCEPTION 'check failed, result: %', r.r1;
	ELSE
		RAISE NOTICE 'OK';
	END IF;

END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION bug_DDB375(_drop_ _drop_ DEFAULT 'drop')
	RETURNS void AS $$
DECLARE
	r record;
	rootdir uuid DEFAULT '00000001-2003-5406-7008-900000000000'::UUID;
	dir uuid DEFAULT '232e2831-bdeb-4f8a-b1ed-5b04a5beba33'::UUID;
	dirname text DEFAULT '/';
	file uuid DEFAULT '42280faa-7afb-441b-8deb-d80003f6e8dd'::UUID;
	filename text DEFAULT 'xxx.avi';
	rev1 uuid DEFAULT '0821509a-56ac-4d0f-a6bb-023bcc920f97'::UUID;
	rev2 uuid DEFAULT 'cb78702d-18e1-43c8-b76f-22cc767b1257'::UUID;
	chunk1 uuid DEFAULT '3932fc08-6fc4-4fb0-9c52-0127f8731572'::UUID;
	chunk2 uuid DEFAULT 'cccd1e1d-058a-4cef-b602-4e9eea3f3933'::UUID;
	chunk_hash text DEFAULT 'AA';
	chunk_size integer DEFAULT 1024;
	chunk_offset integer DEFAULT 0;
	chunk_address text DEFAULT '/dev/zero';
BEGIN
	/*
		последовательность:
			chunk_prepare(rev1)
			insert_revision(rev1, prepare=true)
			chunk_prepare(rev2)
			insert_revision(rev2, prepare=true) -- не должно возникать ошибки
			insert_chunk(rev1)
			insert_revision(rev1)
			insert_revision(rev2)
	*/
	INSERT INTO "user" (username, secret) VALUES ('ddb375', 'ddb375');
	PERFORM begin_life('ddb375', 375);

	/* создание директории */
	SELECT * INTO r FROM directory_create(rootdir, dir, dirname);
	IF r.r_error IS NOT NULL THEN
		RAISE EXCEPTION '1, directory_create: %', r;
	END IF;
	RAISE NOTICE '1, directory_create: %', r;

	/* чанк 1 (подготовка) */
	SELECT * INTO r FROM chunk_prepare(rootdir, chunk_hash, chunk_size);
	IF r.r_error IS NOT NULL THEN
		RAISE EXCEPTION '2, chunk_prepare: %', r;
	END IF;
	RAISE NOTICE '2, chunk_prepare: %', r;

	/* ревизия 1 (подготовка) */
	SELECT * INTO r FROM insert_revision(rootdir, file, rev1, NULL, filename, '', dir, 1, true);
	IF r.r_error IS NOT NULL THEN
		RAISE EXCEPTION '3, insert_revision: %', r;
	END IF;
	RAISE NOTICE '3, insert_revision: %', r;

	/* чанк 2 (подготовка) */
	SELECT * INTO r FROM chunk_prepare(rootdir, chunk_hash, chunk_size);
	IF r.r_error IS NOT NULL THEN
		RAISE EXCEPTION '4, chunk_prepare: %', r;
	END IF;
	RAISE NOTICE '4, chunk_prepare: %', r;

	/* ревизия 2 (подготовка) */
	SELECT * INTO r FROM insert_revision(rootdir, file, rev2, rev1, filename, '', dir, 1, true);
	IF r.r_error IS NOT NULL THEN
		RAISE EXCEPTION '5, insert_revision: %', r;
	END IF;
	RAISE NOTICE '5, insert_revision: %', r;

	/* вставка чанка 1 */
	SELECT * INTO r FROM insert_chunk(rootdir, file, rev1, chunk1, chunk_hash, chunk_size, chunk_offset, chunk_address);
	IF r.r_error IS NOT NULL THEN
		RAISE EXCEPTION '6, insert_chunk: %', r;
	END IF;
	RAISE NOTICE '6, insert_chunk: %', r;

	/* вставка ревизии 1 */
	SELECT * INTO r FROM insert_revision(rootdir, file, rev1, NULL, filename, '', dir, 1, false);
	IF r.r_error IS NOT NULL THEN
		RAISE EXCEPTION '7, insert_revision: %', r;
	END IF;
	RAISE NOTICE '7, insert_revision: %', r;

	/* вставка чанка 2 */
	SELECT * INTO r FROM insert_chunk(rootdir, file, rev2, chunk2, chunk_hash, chunk_size, chunk_offset, chunk_address);
	IF r.r_error IS NOT NULL THEN
		RAISE EXCEPTION '8, insert_chunk: %', r;
	END IF;
	RAISE NOTICE '8, insert_chunk: %', r;

	/* вставка ревизии 2 */
	SELECT * INTO r FROM insert_revision(rootdir, file, rev2, rev1, filename, '', dir, 1, false);
	IF r.r_error IS NOT NULL THEN
		RAISE EXCEPTION '9, insert_revision: %', r;
	END IF;
	RAISE NOTICE '9, insert_revision: %', r;

END $$ LANGUAGE plpgsql;


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

