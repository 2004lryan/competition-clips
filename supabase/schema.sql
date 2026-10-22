-- 竞赛资料收集页的数据库：一张公开可读的表 clips，加三个函数。
-- 页面用 publishable key 访问，所以表只开放读；写入一律走函数，函数先核对口令。
-- 口令只存 sha256 哈希，放在不对外暴露的 clips_private 里，不写进本文件。口令分两种：
--   add   给老师们收链接用，只能新建只有链接的记录；
--   admin 同步脚本回填标题、分类和说明用。
-- 加一个口令：在本机算出哈希（printf %s '<口令>' | shasum -a 256），再执行
--   insert into clips_private.codes (hash, role, label) values ('<哈希>', 'add', '<备注>');
-- 换口令就加新的、删掉旧的那一行。
-- 本文件可以重复执行。

create schema if not exists clips_private;
revoke all on schema clips_private from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on schema clips_private from anon, authenticated';
  end if;
end $$;

create table if not exists clips_private.codes (
  hash text primary key,
  role text not null check (role in ('add', 'admin')),  -- add：只能收链接；admin：同步脚本回填整理结果
  label text not null default '',
  created_at timestamptz not null default now()
);

-- 链接去重用的键：和页面里 urlKey()、同步脚本里 url_key() 是同一个算法，改一处要三处一起改。
-- 首尾去掉空格、制表换行、不换行空格、全角空格和 BOM；协议和主机名不分大小写，路径和参数分大小写；公众号的两种永久链接（/s/<短码>，或 __biz、mid、idx、sn
-- 四个参数，参数值可以为空）各自归一，其余链接去掉协议和末尾斜杠。最后整串转小写。
create or replace function public.clip_url_key(u text) returns text
language plpgsql immutable set search_path = '' as $$
declare
  s text; m text[]; p text; i int; kv jsonb := '{}'::jsonb;
begin
  s := regexp_replace(coalesce(u, ''), '^[ \t\n\r\f\v\u00a0\u3000\ufeff]+|[ \t\n\r\f\v\u00a0\u3000\ufeff]+$', '', 'g');
  s := regexp_replace(s, '[)）】」。，,;；!！]+$', '');
  s := split_part(s, '#', 1);
  m := regexp_match(s, '^(https?://[^/?]+)(.*)$', 'i');
  if m is not null then
    s := lower(m[1]) || coalesce(m[2], '');
  end if;
  m := regexp_match(s, '^https?://mp\.weixin\.qq\.com/s/([A-Za-z0-9_-]+)');
  if m is not null then
    return lower('mp.weixin.qq.com/s/' || m[1]);
  end if;
  m := regexp_match(s, '^https?://mp\.weixin\.qq\.com/s/?\?(.+)$');
  if m is not null then
    foreach p in array string_to_array(m[1], '&') loop
      i := strpos(p, '=');
      if i > 1 then kv := kv || jsonb_build_object(left(p, i - 1), substr(p, i + 1)); end if;
    end loop;
    if kv ? '__biz' and kv ? 'mid' and kv ? 'idx' and kv ? 'sn' then
      return lower('mp.weixin.qq.com/s?__biz=' || (kv ->> '__biz') || '&mid=' || (kv ->> 'mid')
                   || '&idx=' || (kv ->> 'idx') || '&sn=' || (kv ->> 'sn'));
    end if;
    return lower('mp.weixin.qq.com/s?' || m[1]);
  end if;
  return lower(regexp_replace(regexp_replace(s, '/+$', ''), '^https?://', '', 'i'));
end $$;

create table if not exists public.clips (
  id text primary key default ('t-' || replace(gen_random_uuid()::text, '-', '')),
  skill text not null check (skill in ('math', 'stat', 'market', 'innovation')),
  url text not null check (url ~* '^https?://\S+$' and length(url) <= 2000),
  url_key text not null unique,
  title text not null default '',
  account text not null default '',
  contest text not null default '',
  category text not null default '',
  note text not null default '',          -- 一句话：这篇讲什么、什么时候翻
  submitter text not null default '',     -- 贴链接的人自己填的称呼
  fetch_error text not null default '',   -- 抓不下来的原因
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  fetched_at timestamptz                  -- 有值＝已整理
);
create index if not exists clips_skill_created on public.clips (skill, created_at desc);

alter table public.clips enable row level security;
drop policy if exists clips_read on public.clips;
create policy clips_read on public.clips for select using (true);
revoke all on public.clips from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke insert, update, delete, truncate, references, trigger on public.clips from anon, authenticated';
    execute 'grant select on public.clips to anon, authenticated';
  end if;
end $$;

create or replace function clips_private.code_role(p_code text) returns text
language sql stable set search_path = '' as $$
  select c.role from clips_private.codes c
  where c.hash = encode(sha256(convert_to(coalesce(p_code, ''), 'UTF8')), 'hex')
$$;
revoke all on function clips_private.code_role(text) from public;

-- 页面「收进」按钮调用：一次最多 50 条，收过的（按 url_key）跳过。
create or replace function public.clip_add(p_code text, p_skill text, p_urls text[], p_submitter text default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  u text; v_added int := 0; v_dup int := 0; v_bad int := 0; v_n int; v_who text;
begin
  if clips_private.code_role(p_code) is null then
    raise exception '口令不对' using errcode = '28P01';
  end if;
  if p_skill is null or p_skill not in ('math', 'stat', 'market', 'innovation') then
    raise exception '没有这一栏：%', p_skill using errcode = '22023';
  end if;
  if coalesce(cardinality(p_urls), 0) > 50 then
    raise exception '一次最多收 50 条' using errcode = '22023';
  end if;
  v_who := left(btrim(regexp_replace(coalesce(p_submitter, ''), '\s+', ' ', 'g')), 40);
  foreach u in array coalesce(p_urls, '{}'::text[]) loop
    u := btrim(coalesce(u, ''));
    if u !~* '^https?://\S+$' or length(u) > 2000 then
      v_bad := v_bad + 1;
      continue;
    end if;
    insert into public.clips (skill, url, url_key, submitter)
    values (p_skill, u, public.clip_url_key(u), v_who)
    on conflict (url_key) do nothing;
    get diagnostics v_n = row_count;
    if v_n > 0 then v_added := v_added + 1; else v_dup := v_dup + 1; end if;
  end loop;
  return jsonb_build_object('added', v_added, 'dup', v_dup, 'bad', v_bad);
end $$;

-- 同步脚本调用：按 url_key 新建或更新整理结果。id、收录时间、贴链接的人保留第一次的。
create or replace function public.clip_admin_upsert(p_code text, p_rows jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  r jsonb; v_n int := 0; v_key text; v_id text;
begin
  if clips_private.code_role(p_code) is distinct from 'admin' then
    raise exception '口令不对' using errcode = '28P01';
  end if;
  for r in select value from jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) loop
    v_key := public.clip_url_key(r ->> 'url');
    v_id := nullif(r ->> 'id', '');
    -- 同一条记录换了链接（临时链接、检索链接换成永久链接）：新链接没人占就改链接，被别的记录占了就删掉这一条，
    -- 下面按新链接更新那一条
    if v_id is not null and exists (select 1 from public.clips where id = v_id and url_key <> v_key) then
      if exists (select 1 from public.clips where url_key = v_key) then
        delete from public.clips where id = v_id;
      else
        update public.clips set url = btrim(r ->> 'url'), url_key = v_key where id = v_id;
      end if;
    end if;
    insert into public.clips as c (id, skill, url, url_key, title, account, contest, category, note,
                                   submitter, fetch_error, created_at, updated_at, fetched_at)
    values (coalesce(v_id, 't-' || replace(gen_random_uuid()::text, '-', '')),
            r ->> 'skill', btrim(r ->> 'url'), v_key,
            coalesce(r ->> 'title', ''), coalesce(r ->> 'account', ''), coalesce(r ->> 'contest', ''),
            coalesce(r ->> 'category', ''), coalesce(r ->> 'note', ''), coalesce(r ->> 'submitter', ''),
            coalesce(r ->> 'fetch_error', ''), coalesce((r ->> 'created_at')::timestamptz, now()), now(),
            (r ->> 'fetched_at')::timestamptz)
    on conflict (url_key) do update set
      skill = excluded.skill, title = excluded.title, account = excluded.account,
      contest = excluded.contest, category = excluded.category, note = excluded.note,
      fetch_error = excluded.fetch_error, fetched_at = excluded.fetched_at, updated_at = now(),
      submitter = case when c.submitter = '' then excluded.submitter else c.submitter end;
    v_n := v_n + 1;
  end loop;
  return jsonb_build_object('upserted', v_n);
end $$;

-- 同步脚本调用：删掉指定 id（收错的、重复的、不相干的）。
create or replace function public.clip_admin_delete(p_code text, p_ids text[])
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_n int;
begin
  if clips_private.code_role(p_code) is distinct from 'admin' then
    raise exception '口令不对' using errcode = '28P01';
  end if;
  delete from public.clips where id = any (coalesce(p_ids, '{}'::text[]));
  get diagnostics v_n = row_count;
  return jsonb_build_object('deleted', v_n);
end $$;

revoke all on function public.clip_add(text, text, text[], text) from public;
revoke all on function public.clip_admin_upsert(text, jsonb) from public;
revoke all on function public.clip_admin_delete(text, text[]) from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'grant execute on function public.clip_add(text, text, text[], text) to anon, authenticated';
    execute 'grant execute on function public.clip_admin_upsert(text, jsonb) to anon, authenticated';
    execute 'grant execute on function public.clip_admin_delete(text, text[]) to anon, authenticated';
  end if;
end $$;
