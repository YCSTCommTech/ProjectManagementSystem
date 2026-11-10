-- =====================================================================
-- JARVIS v3 setup: real accounts + locked-down data
-- Run the WHOLE file once in Supabase > SQL Editor. Safe to run again.
-- WARNING: this erases all the test (character) data.
-- =====================================================================

-- ---------- 1. People (the roster) ----------
create table if not exists public.people (
  id uuid primary key references auth.users(id) on delete cascade,
  pid text unique not null,               -- short id the app uses ('t' = the teacher)
  username text unique not null,
  name text not null,
  role text not null check (role in ('teacher','student')),
  grad int,
  major text,
  active boolean not null default true,
  created_at timestamptz not null default now()
);
alter table public.people enable row level security;

-- ---------- 2. Data tables (same shape as before) ----------
do $$
declare t text;
begin
  foreach t in array array['projects','assignments','items','notifs','syncs','asks','lessons','polls','checkins','weeks','settings','events','bank','reminders','todos'] loop
    execute format('create table if not exists public.%I (id text primary key, data jsonb not null default ''{}''::jsonb, updated_at timestamptz not null default now())', t);
    execute format('alter table public.%I add column if not exists updated_at timestamptz not null default now()', t);
    execute format('alter table public.%I enable row level security', t);
    execute format('alter table public.%I replica identity full', t);
    execute format('drop policy if exists "test open access" on public.%I', t);
    execute format('drop policy if exists "jarvis read" on public.%I', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
    execute format('truncate public.%I', t);   -- wipe the character test data
    if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename=t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;

-- Old wide-open test helpers are removed
drop function if exists public.patch_row(text, text, jsonb);
drop function if exists public.append_row(text, text, text, jsonb);

-- ---------- 3. Who am I? ----------
create or replace function public.jarvis_me() returns text
language sql stable security definer set search_path = public as $$
  select pid from people where id = auth.uid() and active
$$;
create or replace function public.jarvis_is_teacher() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from people where id = auth.uid() and role = 'teacher' and active)
$$;
create or replace function public.jarvis_role(proj_id text, who text) returns text
language sql stable security definer set search_path = public as $$
  select case when p.data->>'owner' = who then 'admin' else p.data->'roles'->>who end from projects p where p.id = proj_id
$$;
create or replace function public.jarvis_can_see_project(proj_id text) returns boolean
language sql stable security definer set search_path = public as $$
  select jarvis_is_teacher() or exists(
    select 1 from projects p where p.id = proj_id
      and ((p.data->'roles') ? jarvis_me() or p.data->>'owner' = jarvis_me() or coalesce((p.data->>'private')::boolean, false) = false))
$$;
create or replace function public.jarvis_to_includes(d jsonb, who text) returns boolean
language sql immutable as $$
  select d->>'to' = 'all' or (jsonb_typeof(d->'to') = 'array' and (d->'to') ? who)
$$;
create or replace function public.jarvis_can_see_item(d jsonb) returns boolean
language sql stable security definer set search_path = public as $$
  select d is not null and (
    jarvis_is_teacher()
    or coalesce(d->'assignees', '[]'::jsonb) ? jarvis_me()
    or (d->>'projectId' is not null and jarvis_can_see_project(d->>'projectId'))
    or exists(select 1 from asks a where a.data->>'itemId' = d->>'id' and a.data->>'kind' = 'feedback' and jarvis_to_includes(a.data, jarvis_me())))
$$;

-- ---------- 4. Who can READ what ----------
drop policy if exists "jarvis read" on public.people;
create policy "jarvis read" on public.people for select to authenticated using (jarvis_me() is not null);
drop policy if exists "jarvis teacher edit" on public.people;
create policy "jarvis teacher edit" on public.people for update to authenticated using (jarvis_is_teacher()) with check (jarvis_is_teacher());
revoke all on public.people from anon, authenticated;
grant select on public.people to authenticated;
grant update (name, grad, major) on public.people to authenticated;

create policy "jarvis read" on public.projects for select to authenticated using (jarvis_can_see_project(id));
create policy "jarvis read" on public.items for select to authenticated using (jarvis_can_see_item(data));
create policy "jarvis read" on public.assignments for select to authenticated using (jarvis_me() is not null);
create policy "jarvis read" on public.notifs for select to authenticated using (jarvis_is_teacher() or data->>'to' = jarvis_me() or data->>'to' = 'all');
create policy "jarvis read" on public.syncs for select to authenticated using (jarvis_is_teacher());
create policy "jarvis read" on public.asks for select to authenticated using (
  jarvis_is_teacher() or data->>'by' = jarvis_me() or data->>'kind' = 'lesson'
  or (data->>'kind' in ('feedback','merge') and jarvis_to_includes(data, jarvis_me()))
  or (data->>'kind' = 'feedback' and data->>'itemId' is not null and jarvis_can_see_item((select i.data from items i where i.id = data->>'itemId')))
  or (data->>'kind' = 'feedback' and data->>'itemId' is null and data->>'projectId' is not null and jarvis_can_see_project(data->>'projectId')));
create policy "jarvis read" on public.lessons for select to authenticated using (jarvis_me() is not null);
create policy "jarvis read" on public.polls for select to authenticated using (jarvis_me() is not null);
create policy "jarvis read" on public.checkins for select to authenticated using (jarvis_is_teacher() or data->>'by' = jarvis_me());
create policy "jarvis read" on public.weeks for select to authenticated using (jarvis_is_teacher() or data->>'by' = jarvis_me());
create policy "jarvis read" on public.events for select to authenticated using (jarvis_is_teacher() or data->>'status' = 'approved' or data->>'by' = jarvis_me());
create policy "jarvis read" on public.bank for select to authenticated using (jarvis_is_teacher() or data->>'status' = 'ready' or data->>'by' = jarvis_me());
create policy "jarvis read" on public.reminders for select to authenticated using (data->>'by' = jarvis_me() or (data->>'to' = jarvis_me() and coalesce((data->>'when')::bigint, 0) <= (extract(epoch from now()) * 1000)::bigint));
create policy "jarvis read" on public.todos for select to authenticated using (data->>'by' = jarvis_me());
create policy "jarvis read" on public.settings for select to authenticated using (
  jarvis_is_teacher() or id like 'profile\_%' or id like 'week\_%' or id = 'mp_config'
  or (id like 'claim\_%' and data->>'by' = jarvis_me()));

-- ---------- 5. Helpers for the write rules ----------
create or replace function public.jarvis_changed(o jsonb, n jsonb) returns text[]
language sql immutable as $$
  select coalesce(array_agg(k), '{}') from (
    select k from (select jsonb_object_keys(coalesce(o,'{}'::jsonb)) k union select jsonb_object_keys(coalesce(n,'{}'::jsonb))) ks
    where coalesce(o->k, 'null'::jsonb) is distinct from coalesce(n->k, 'null'::jsonb)) x
$$;
-- returns the newly added elements if n is o plus extra items at the end, otherwise NULL
create or replace function public.jarvis_appended(o jsonb, n jsonb) returns jsonb
language plpgsql immutable as $$
declare lo int := coalesce(jsonb_array_length(coalesce(o,'[]'::jsonb)),0); ln int; head jsonb; tail jsonb;
begin
  if n is null or jsonb_typeof(n) <> 'array' then return null; end if;
  ln := jsonb_array_length(n);
  if ln < lo then return null; end if;
  select coalesce(jsonb_agg(e order by i), '[]'::jsonb) into head from jsonb_array_elements(n) with ordinality as x(e,i) where i <= lo;
  if head is distinct from coalesce(o,'[]'::jsonb) then return null; end if;
  select coalesce(jsonb_agg(e order by i), '[]'::jsonb) into tail from jsonb_array_elements(n) with ordinality as x(e,i) where i > lo;
  return tail;
end $$;
-- true if every appended element was written by `who`
create or replace function public.jarvis_append_ok(o jsonb, n jsonb, who text) returns boolean
language sql immutable as $$
  select jarvis_appended(o, n) is not null
     and not exists(select 1 from jsonb_array_elements(jarvis_appended(o, n)) e where e->>'by' is distinct from who)
$$;
-- true if the two arrays of ids differ only by `who` being added or removed
create or replace function public.jarvis_toggle_ok(o jsonb, n jsonb, who text) returns boolean
language sql immutable as $$
  select coalesce((select array_agg(x order by x) from (
      (select jsonb_array_elements_text(coalesce(o,'[]'::jsonb)) except select jsonb_array_elements_text(coalesce(n,'[]'::jsonb)))
      union
      (select jsonb_array_elements_text(coalesce(n,'[]'::jsonb)) except select jsonb_array_elements_text(coalesce(o,'[]'::jsonb)))) d(x)), '{}') <@ array[who]
$$;
create or replace function public.jarvis_deny(msg text) returns void language plpgsql as $$
begin raise exception 'JARVIS: %', msg using errcode = '42501'; end $$;

-- ---------- 6. The write rules (students; the teacher can do anything) ----------
create or replace function public.jarvis_check(tbl text, o jsonb, n jsonb, me text) returns void
language plpgsql stable security definer set search_path = public as $$
declare ch text[] := jarvis_changed(o, n); r text; r2 text; d jsonb := coalesce(n, o); k text;
begin
  if tbl = 'projects' then
    if o is null then
      if n->>'owner' is distinct from me or n->'roles'->>me is distinct from 'admin' or coalesce(n->>'parentId','') <> '' then perform jarvis_deny('new projects must be yours'); end if;
      return;
    end if;
    r := jarvis_role(o->>'id', me);
    if n is null then if r = 'admin' then return; end if; perform jarvis_deny('only a project admin can delete it'); end if;
    if 'owner' = any(ch) then perform jarvis_deny('the owner can’t be changed'); end if;
    if 'parentId' = any(ch) and coalesce(n->>'parentId','') <> '' then perform jarvis_deny('use Combine to put a project inside another'); end if;
    if 'thread' = any(ch) and not jarvis_append_ok(o->'thread', n->'thread', me) then perform jarvis_deny('updates can only be added'); end if;
    if r = 'admin' then return; end if;
    if r = 'editor' and ch <@ array['description','files','thread','eventId'] then return; end if;
    perform jarvis_deny('you can’t change this project');

  elsif tbl = 'items' then
    if o is null then
      if n->>'source' = 'task' then
        r := jarvis_role(n->>'projectId', me);
        if r in ('admin','editor') then return; end if;
        perform jarvis_deny('you need to be an editor on that project');
      end if;
      if n->>'source' = 'assignment' and n->>'id' like 'iw\_%' and n->>'assignmentId' like 'aw\_%' and n->>'status' = 'not' then return; end if;
      perform jarvis_deny('only Mr. P can create assignments');
    end if;
    if n is null then
      if o->>'source' = 'task' and jarvis_role(o->>'projectId', me) in ('admin','editor') then return; end if;
      perform jarvis_deny('you can’t delete this');
    end if;
    if ch && array['source','assignmentId','syncId','missingId','id'] then perform jarvis_deny('that can’t be changed'); end if;
    if 'history' = any(ch) and not jarvis_append_ok(o->'history', n->'history', me) then perform jarvis_deny('history can only be added to'); end if;
    if 'thread' = any(ch) and not jarvis_append_ok(o->'thread', n->'thread', me) then perform jarvis_deny('updates can only be added'); end if;
    if o->>'source' = 'assignment' then
      if not (coalesce(o->'assignees','[]'::jsonb) ? me) then perform jarvis_deny('this isn’t your assignment'); end if;
      if not ch <@ array['status','files','thread','history'] then perform jarvis_deny('only Mr. P can change that'); end if;
      if 'status' = any(ch) and (n->>'status' = 'done' or o->>'status' = 'done') then perform jarvis_deny('only Mr. P marks assignments Done'); end if;
      return;
    end if;
    r := jarvis_role(o->>'projectId', me);
    if r in ('admin','editor') then
      if 'projectId' = any(ch) then
        r2 := jarvis_role(n->>'projectId', me);
        if coalesce(r2,'') not in ('admin','editor') then perform jarvis_deny('you need to be an editor on the other project'); end if;
      end if;
      return;
    end if;
    if coalesce(o->'assignees','[]'::jsonb) ? me and ch <@ array['status','files','thread','history','when'] then return; end if;
    perform jarvis_deny('you can’t change this item');

  elsif tbl = 'assignments' then
    if o is null and n->>'id' = 'aw_' || (n->>'weekStart') and (n->>'weekly')::boolean then return; end if;
    perform jarvis_deny('only Mr. P can change assignments');

  elsif tbl = 'notifs' then
    if o is null and n->>'by' = me then return; end if;
    if o is not null and n is not null and ch <@ array['readBy'] and jarvis_appended(o->'readBy', n->'readBy') is not null
       and not exists(select 1 from jsonb_array_elements_text(jarvis_appended(o->'readBy', n->'readBy')) e where e <> me) then return; end if;
    perform jarvis_deny('notification change not allowed');

  elsif tbl = 'asks' then
    if o is null then
      if n->>'by' is distinct from me or coalesce(jsonb_array_length(n->'replies'),0) > 0 then perform jarvis_deny('asks must be yours'); end if;
      if n->>'kind' = 'lesson' and (n->'plus') is distinct from jsonb_build_array(me) then perform jarvis_deny('bad lesson request'); end if;
      if n->>'kind' = 'merge' and jarvis_role(n->>'projectId', me) is distinct from 'admin' then perform jarvis_deny('only a project admin can ask to combine it'); end if;
      if coalesce(n->>'kind','') not in ('feedback','help','lesson','merge') then perform jarvis_deny('bad ask'); end if;
      return;
    end if;
    if n is null then perform jarvis_deny('asks can’t be deleted'); end if;
    if 'replies' = any(ch) and not jarvis_append_ok(o->'replies', n->'replies', me) then perform jarvis_deny('replies can only be added'); end if;
    if 'plus' = any(ch) and (o->>'kind' <> 'lesson' or not jarvis_toggle_ok(o->'plus', n->'plus', me)) then perform jarvis_deny('you can only +1 for yourself'); end if;
    if o->>'by' = me and ch <@ array['open','note','replies','plus'] then return; end if;
    if o->>'kind' = 'merge' and jarvis_role(o->>'targetId', me) = 'admin' and ch <@ array['open','result','replies'] then return; end if;
    if ch <@ array['replies','plus'] and (o->>'kind' = 'lesson' or jarvis_to_includes(o, me)
        or (o->>'kind' = 'feedback' and (o->>'itemId' is not null and jarvis_can_see_item((select i.data from items i where i.id = o->>'itemId'))))) then return; end if;
    perform jarvis_deny('you can’t change this ask');

  elsif tbl = 'lessons' then
    if o is not null and n is not null and ch <@ array['signups'] and jarvis_toggle_ok(o->'signups', n->'signups', me) then
      if jsonb_array_length(n->'signups') > jsonb_array_length(coalesce(o->'signups','[]'::jsonb)) then
        if jsonb_array_length(n->'signups') > coalesce((o->>'seats')::int, 0) then perform jarvis_deny('that lesson is full'); end if;
      end if;
      return;
    end if;
    perform jarvis_deny('only Mr. P can change lessons');

  elsif tbl = 'polls' then
    if o is not null and n is not null and ch <@ array['responses'] and coalesce((o->>'open')::boolean, false)
       and jarvis_append_ok(o->'responses', n->'responses', me) then return; end if;
    perform jarvis_deny('you can only answer open polls');

  elsif tbl = 'checkins' then
    if n is null then perform jarvis_deny('check-ins can’t be deleted'); end if;
    if n->>'by' = me and n->>'id' = 'ci_' || me || '_' || (n->>'date') and (o is null or o->>'by' = me) then return; end if;
    perform jarvis_deny('that’s not your check-in');

  elsif tbl = 'weeks' then
    if n is null then perform jarvis_deny('weekly reports can’t be deleted'); end if;
    if n->>'by' = me and n->>'id' = 'wk_' || me || '_' || (n->>'weekStart') and (o is null or o->>'by' = me) and not ('days' = any(ch)) then return; end if;
    perform jarvis_deny('that’s not your weekly report');

  elsif tbl = 'settings' then
    k := d->>'id';
    if k = 'profile_' || me then
      if n is null then perform jarvis_deny('profiles can’t be deleted'); end if;
      if 'img' = any(ch) and n->'img' is not null and n->'img' <> 'null'::jsonb then perform jarvis_deny('pictures need Mr. P’s approval'); end if;
      if ch <@ array['id','color','shape','mode','text','imgPending','img','simple','nick'] then return; end if;
      perform jarvis_deny('profile change not allowed');
    end if;
    if k like 'claim\_' || me || '\_%' and d->>'by' = me then
      if n is null then
        if coalesce(o->>'status','planned') in ('planned','returned') then return; end if;
        perform jarvis_deny('counted work can’t be removed');
      end if;
      if coalesce(o->>'status','planned') not in ('planned','returned') and ch <> '{}' then perform jarvis_deny('that’s waiting for Mr. P'); end if;
      if coalesce(n->>'status','planned') not in ('planned','submitted') then perform jarvis_deny('only Mr. P counts work'); end if;
      if ch && array['mp','creditedAt','by','target'] and o is not null then perform jarvis_deny('that can’t be changed'); end if;
      if o is null and (n->>'status' <> 'planned' or n ? 'mp') then perform jarvis_deny('new tags start as planned'); end if;
      return;
    end if;
    perform jarvis_deny('only Mr. P can change that setting');

  elsif tbl = 'events' then
    if o is null then
      if n->>'by' is distinct from me or coalesce(n->>'status','') <> 'pending' then perform jarvis_deny('new events wait for Mr. P’s approval'); end if;
      return;
    end if;
    if o->>'by' is distinct from me or coalesce(o->>'status','') <> 'pending' then perform jarvis_deny('only Mr. P can change this event'); end if;
    if n is null then return; end if;
    if ch && array['status','by','note'] then perform jarvis_deny('only Mr. P approves events'); end if;
    return;

  elsif tbl = 'bank' then
    if o is null then
      if n->>'by' is distinct from me or coalesce(n->>'status','') <> 'raw' then perform jarvis_deny('suggestions go to Mr. P first'); end if;
      return;
    end if;
    if n is null then
      if o->>'by' = me and o->>'status' = 'raw' then return; end if;
      perform jarvis_deny('only a teacher can remove bank cards');
    end if;
    if o->>'by' = me and o->>'status' = 'raw' and not (ch && array['status','by']) then return; end if;
    if o->>'status' = 'ready' and o->>'type' = 'idea' and ch <@ array['starts'] and jarvis_append_ok(o->'starts', n->'starts', me) then return; end if;
    if o->>'status' = 'ready' and o->>'type' = 'request' and ch <@ array['hands'] and jarvis_toggle_ok(o->'hands', n->'hands', me) then return; end if;
    perform jarvis_deny('only a teacher can change bank cards');

  elsif tbl = 'reminders' then
    if o is null then
      if n->>'by' is distinct from me or n->>'to' is distinct from me then perform jarvis_deny('you can only set reminders for yourself'); end if;
      return;
    end if;
    if n is null then
      if o->>'by' = me then return; end if;
      perform jarvis_deny('only the person who set a reminder can delete it');
    end if;
    if o->>'by' = me and not ('by' = any(ch)) and n->>'to' is not distinct from o->>'to' then return; end if;
    if o->>'to' = me and ch <@ array['done','doneAt','when','notified','snoozes'] then return; end if;
    perform jarvis_deny('that reminder belongs to someone else');

  elsif tbl = 'todos' then
    if (o is null or o->>'by' = me) and (n is null or n->>'by' = me) then return; end if;
    perform jarvis_deny('that list belongs to someone else');

  elsif tbl = 'syncs' then
    perform jarvis_deny('only Mr. P can do that');
  else
    perform jarvis_deny('unknown table');
  end if;
end $$;

-- ---------- 7. The only way to save anything ----------
create or replace function public.jarvis_write(op text, tbl text, rid text, payload jsonb default null, k text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare me text := jarvis_me(); t boolean := jarvis_is_teacher(); o jsonb; n jsonb;
begin
  if me is null then perform jarvis_deny('please sign in'); end if;
  if tbl not in ('projects','assignments','items','notifs','syncs','asks','lessons','polls','checkins','weeks','settings','events','bank','reminders','todos') then perform jarvis_deny('bad table'); end if;
  execute format('select data from public.%I where id = $1 for update', tbl) into o using rid;
  if op = 'put' then n := payload;
  elsif op = 'patch' then n := coalesce(o, '{}'::jsonb) || payload;
  elsif op = 'append' then
    if o is null then perform jarvis_deny('that was deleted'); end if;
    n := jsonb_set(o, array[k], coalesce(o->k, '[]'::jsonb) || payload);
  elsif op = 'delete' then n := null;
  else perform jarvis_deny('bad operation'); end if;
  if n is not null then n := jsonb_set(n, '{id}', to_jsonb(rid)); end if;
  if not t then perform jarvis_check(tbl, o, n, me); end if;
  if n is null then execute format('delete from public.%I where id = $1', tbl) using rid;
  elsif o is null then execute format('insert into public.%I (id, data) values ($1, $2)', tbl) using rid, n;
  else execute format('update public.%I set data = $2, updated_at = now() where id = $1', tbl) using rid, n;
  end if;
  return n;
end $$;
revoke all on function public.jarvis_write(text, text, text, jsonb, text) from public, anon;
grant execute on function public.jarvis_write(text, text, text, jsonb, text) to authenticated;

-- ---------- 8. Combining projects (runs on the server so nobody needs extra access) ----------
create or replace function public.jarvis_stamp() returns jsonb language sql stable as $$
  select jsonb_build_object('ts', (extract(epoch from now()) * 1000)::bigint, 'at', to_char(now() at time zone 'America/New_York', 'Mon FMDD, FMHH12:MI AM'))
$$;
create or replace function public.jarvis_merge(p_id text, t_id text, mode text, ask_id text default null) returns text
language plpgsql security definer set search_path = public as $$
declare me text := jarvis_me(); pd jsonb; td jsonb; a jsonb; ok boolean := false; st jsonb := jarvis_stamp(); nid text; status text; r record;
begin
  if me is null then perform jarvis_deny('please sign in'); end if;
  select data into pd from projects where id = p_id for update;
  select data into td from projects where id = t_id for update;
  if pd is null or td is null or p_id = t_id then perform jarvis_deny('project not found'); end if;
  if mode not in ('nest','convert') then perform jarvis_deny('bad mode'); end if;
  if jarvis_is_teacher() then ok := true;
  elsif jarvis_role(p_id, me) = 'admin' and jarvis_role(t_id, me) = 'admin' then ok := true;
  elsif ask_id is not null and jarvis_role(t_id, me) = 'admin' then
    select data into a from asks where id = ask_id;
    ok := a is not null and a->>'kind' = 'merge' and coalesce((a->>'open')::boolean,false) and a->>'projectId' = p_id and a->>'targetId' = t_id and a->>'mode' = mode
          and jarvis_role(p_id, a->>'by') = 'admin';
  end if;
  if not ok then perform jarvis_deny('you can’t combine these projects'); end if;
  if coalesce(td->>'parentId','') <> '' then perform jarvis_deny('the bigger project is already inside another'); end if;
  if exists(select 1 from projects where data->>'parentId' = p_id) then perform jarvis_deny('take the projects inside it out first'); end if;

  if mode = 'nest' then
    update projects set data = jsonb_set(data, '{parentId}', to_jsonb(t_id)) || jsonb_build_object('thread', coalesce(data->'thread','[]'::jsonb) ||
      jsonb_build_array(jsonb_build_object('id','u'||substr(md5(random()::text),1,10),'by',me,'text','Moved inside “'||(td->>'name')||'”','sys',true) || st)), updated_at = now() where id = p_id;
    update projects set data = data || jsonb_build_object('thread', coalesce(data->'thread','[]'::jsonb) ||
      jsonb_build_array(jsonb_build_object('id','u'||substr(md5(random()::text),1,10),'by',me,'text','“'||(pd->>'name')||'” is now part of this project','sys',true) || st)), updated_at = now() where id = t_id;
    nid := null;
  else
    select case when count(*) > 0 and bool_and(data->>'status' in ('done','sub')) then 'done' when bool_or(data->>'status' <> 'not') then 'work' else 'not' end
      into status from items where data->>'projectId' = p_id;
    nid := 'i' || substr(md5(random()::text), 1, 12);
    insert into items (id, data) values (nid, jsonb_build_object(
      'id', nid, 'source','task', 'title', pd->>'name', 'description', coalesce(pd->>'description',''),
      'assignees', coalesce((select jsonb_agg(key) from jsonb_each_text(coalesce(pd->'roles','{}'::jsonb)) where value <> 'viewer' and key <> 't'), '[]'::jsonb),
      'status', coalesce(status,'not'), 'due','', 'priority','med', 'projectId', t_id, 'parentId', null,
      'files', coalesce(pd->'files','[]'::jsonb), 'thread', coalesce(pd->'thread','[]'::jsonb),
      'history', jsonb_build_array(jsonb_build_object('kind','converted','by',me,'from',pd->>'name') || st)));
    -- everything moves over; top-level items go under the new item, deeper layers keep their place
    update items set data = data || jsonb_build_object('projectId', t_id,
        'history', coalesce(data->'history','[]'::jsonb) || jsonb_build_array(jsonb_build_object('kind','moved','by',me,'from',pd->>'name','to',td->>'name') || st))
      || case when coalesce(data->>'parentId','') = '' then jsonb_build_object('parentId', nid) else '{}'::jsonb end,
      updated_at = now()
      where data->>'projectId' = p_id and id <> nid;
    -- people from the smaller project join the bigger one
    update projects set data = jsonb_set(data, '{roles}', coalesce((select jsonb_object_agg(key, case when value = 'viewer' then 'viewer' else 'editor' end) from jsonb_each_text(coalesce(pd->'roles','{}'::jsonb))), '{}'::jsonb) || coalesce(data->'roles','{}'::jsonb))
      || jsonb_build_object('thread', coalesce(data->'thread','[]'::jsonb) || jsonb_build_array(jsonb_build_object('id','u'||substr(md5(random()::text),1,10),'by',me,'text','“'||(pd->>'name')||'” was turned into an item in this project','sys',true) || st)),
      updated_at = now() where id = t_id;
    update asks set data = data || jsonb_build_object('projectId', t_id, 'itemId', coalesce(data->>'itemId', nid)), updated_at = now() where data->>'projectId' = p_id and data->>'kind' <> 'merge';
    update asks set data = data || jsonb_build_object('open', false), updated_at = now() where data->>'kind' = 'merge' and (data->>'projectId' = p_id or data->>'targetId' = p_id) and coalesce(id,'') <> coalesce(ask_id,'');
    update checkins set data = jsonb_set(data, '{active}', (select coalesce(jsonb_agg(case when e = to_jsonb('p:'||p_id) then to_jsonb('i:'||nid) else e end), '[]'::jsonb) from jsonb_array_elements(coalesce(data->'active','[]'::jsonb)) e)), updated_at = now()
      where data->'active' ? ('p:'||p_id);
    update projects set data = data || jsonb_build_object('parentId', null), updated_at = now() where data->>'parentId' = p_id;
    delete from projects where id = p_id;
  end if;
  if ask_id is not null then
    update asks set data = data || jsonb_build_object('open', false, 'result', 'approved'), updated_at = now() where id = ask_id;
  end if;
  return nid;
end $$;
revoke all on function public.jarvis_merge(text, text, text, text) from public, anon;
grant execute on function public.jarvis_merge(text, text, text, text) to authenticated;

-- ---------- 9. Teacher-only: wipe and restore from a backup ----------
create or replace function public.jarvis_restore(backup jsonb) returns int
language plpgsql security definer set search_path = public as $$
declare t text; n int := 0; rj jsonb;
begin
  if not jarvis_is_teacher() then perform jarvis_deny('only Mr. P can restore'); end if;
  foreach t in array array['projects','assignments','items','notifs','syncs','asks','lessons','polls','checkins','weeks','settings','events','bank'] loop
    execute format('delete from public.%I', t);
    for rj in select value from jsonb_array_elements(coalesce(backup->t, '[]'::jsonb)) loop
      if rj->>'id' is not null then
        execute format('insert into public.%I (id, data) values ($1, $2) on conflict (id) do update set data = excluded.data', t) using rj->>'id', rj;
        n := n + 1;
      end if;
    end loop;
  end loop;
  return n;
end $$;
revoke all on function public.jarvis_restore(jsonb) from public, anon;
grant execute on function public.jarvis_restore(jsonb) to authenticated;

-- ---------- 10. Everything else is locked ----------
revoke execute on function public.jarvis_check(text, jsonb, jsonb, text) from public, anon, authenticated;

-- =====================================================================
-- AFTER running this file: create your teacher account (see the steps in chat),
-- then run the two lines below with YOUR username in both places.
--   insert into public.people (id, pid, username, name, role)
--   select id, 't', 'mrp', 'Mr. P', 'teacher' from auth.users where email = 'mrp@jarvis.local';
-- =====================================================================
-- JARVIS 2.0.0 cumulative update (includes everything through 1.5.14).
-- 2.0 adds: email opt-out (contacts.optout), urgent safety-alert emails to the teacher, Student Assistant activity log rows (alog_*), written by the assistant, read by teachers.
-- =====================================================================
-- JARVIS update for v1.5.14 (Student Assistant role + everything before). Run once in Supabase > SQL Editor.
-- Includes every update since 0.91, so it works whichever ones you ran.
-- Does NOT erase anything. Safe to run again.
-- =====================================================================

alter table public.people drop constraint if exists people_role_check;
alter table public.people add constraint people_role_check check (role in ('teacher','student','wall'));

alter table public.people add column if not exists helper boolean not null default false;
grant update (helper) on public.people to authenticated;  -- teachers only (policy "jarvis teacher edit")

create or replace function public.jarvis_is_helper() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from people where id = auth.uid() and role = 'student' and helper and active)
$$;


create or replace function public.jarvis_is_wall() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from people where id = auth.uid() and role = 'wall')
$$;
revoke all on function public.jarvis_is_wall() from public, anon;
grant execute on function public.jarvis_is_wall() to authenticated;

create table if not exists public.events (id text primary key, data jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now());
alter table public.events enable row level security;
alter table public.events replica identity full;
revoke all on public.events from anon, authenticated;
grant select on public.events to authenticated;
drop policy if exists "jarvis read" on public.events;
create policy "jarvis read" on public.events for select to authenticated using (jarvis_is_teacher() or jarvis_is_helper() or data->>'status' = 'approved' or data->>'by' = jarvis_me());
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='events') then
    alter publication supabase_realtime add table public.events;
  end if;
end $$;

create table if not exists public.bank (id text primary key, data jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now());
alter table public.bank enable row level security;
alter table public.bank replica identity full;
revoke all on public.bank from anon, authenticated;
grant select on public.bank to authenticated;
drop policy if exists "jarvis read" on public.bank;
create policy "jarvis read" on public.bank for select to authenticated using (jarvis_is_teacher() or jarvis_is_helper() or data->>'status' = 'ready' or data->>'by' = jarvis_me());
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='bank') then
    alter publication supabase_realtime add table public.bank;
  end if;
end $$;

create table if not exists public.reminders (id text primary key, data jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now());
alter table public.reminders enable row level security;
alter table public.reminders replica identity full;
revoke all on public.reminders from anon, authenticated;
grant select on public.reminders to authenticated;
drop policy if exists "jarvis read" on public.reminders;
create policy "jarvis read" on public.reminders for select to authenticated using (data->>'by' = jarvis_me() or (data->>'to' = jarvis_me() and coalesce((data->>'when')::bigint, 0) <= (extract(epoch from now()) * 1000)::bigint));
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='reminders') then
    alter publication supabase_realtime add table public.reminders;
  end if;
end $$;

create table if not exists public.todos (id text primary key, data jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now());
alter table public.todos enable row level security;
alter table public.todos replica identity full;
revoke all on public.todos from anon, authenticated;
grant select on public.todos to authenticated;
drop policy if exists "jarvis read" on public.todos;
create policy "jarvis read" on public.todos for select to authenticated using (data->>'by' = jarvis_me());
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='todos') then
    alter publication supabase_realtime add table public.todos;
  end if;
end $$;

create table if not exists public.reflections (id text primary key, data jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now());
alter table public.reflections enable row level security;
alter table public.reflections replica identity full;
revoke all on public.reflections from anon, authenticated;
grant select on public.reflections to authenticated;
drop policy if exists "jarvis read" on public.reflections;
create policy "jarvis read" on public.reflections for select to authenticated using (jarvis_is_teacher() or data->>'by' = jarvis_me());
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='reflections') then
    alter publication supabase_realtime add table public.reflections;
  end if;
end $$;

create table if not exists public.broadcast (id text primary key, data jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now());
alter table public.broadcast enable row level security;
alter table public.broadcast replica identity full;
revoke all on public.broadcast from anon, authenticated;
grant select on public.broadcast to authenticated;
drop policy if exists "jarvis read" on public.broadcast;
create policy "jarvis read" on public.broadcast for select to authenticated using (true);
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='broadcast') then
    alter publication supabase_realtime add table public.broadcast;
  end if;
end $$;

-- Updated rules
create or replace function public.jarvis_check(tbl text, o jsonb, n jsonb, me text) returns void
language plpgsql stable security definer set search_path = public as $$
declare ch text[] := jarvis_changed(o, n); r text; r2 text; d jsonb := coalesce(n, o); k text;
begin
  if jarvis_is_helper() and (tbl in ('broadcast','bank','lessons','polls','events')
     or (tbl = 'settings' and (d->>'id' like 'post\_%' or d->>'id' = 'wall_cfg' or (d->>'id' like 'alog\_%' and d->>'by' = me)))) then return; end if;
  if tbl = 'projects' then
    if o is null then
      if n->>'owner' is distinct from me or n->'roles'->>me is distinct from 'admin' or coalesce(n->>'parentId','') <> '' then perform jarvis_deny('new projects must be yours'); end if;
      return;
    end if;
    r := jarvis_role(o->>'id', me);
    if n is null then if r = 'admin' then return; end if; perform jarvis_deny('only a project admin can delete it'); end if;
    if 'owner' = any(ch) then perform jarvis_deny('the owner can’t be changed'); end if;
    if 'parentId' = any(ch) and coalesce(n->>'parentId','') <> '' then perform jarvis_deny('use Combine to put a project inside another'); end if;
    if 'thread' = any(ch) and not jarvis_append_ok(o->'thread', n->'thread', me) then perform jarvis_deny('updates can only be added'); end if;
    if coalesce((o->>'completed')::boolean,false) and not coalesce((n->>'completed')::boolean,false) then perform jarvis_deny('only a teacher can reopen a finished project'); end if;
    if r = 'admin' then return; end if;
    if r = 'editor' and ch <@ array['description','files','thread','eventId','onWall','wallBlurb','nextStep','nextDate'] then return; end if;
    perform jarvis_deny('you can’t change this project');

  elsif tbl = 'items' then
    if o is null then
      if n->>'source' = 'task' then
        r := jarvis_role(n->>'projectId', me);
        if r in ('admin','editor') then return; end if;
        perform jarvis_deny('you need to be an editor on that project');
      end if;
      if n->>'source' = 'assignment' and n->>'id' like 'iw\_%' and n->>'assignmentId' like 'aw\_%' and n->>'status' = 'not' then return; end if;
      perform jarvis_deny('only Mr. P can create assignments');
    end if;
    if n is null then
      if o->>'source' = 'task' and jarvis_role(o->>'projectId', me) in ('admin','editor') then return; end if;
      perform jarvis_deny('you can’t delete this');
    end if;
    if ch && array['source','assignmentId','syncId','missingId','id'] then perform jarvis_deny('that can’t be changed'); end if;
    if 'history' = any(ch) and not jarvis_append_ok(o->'history', n->'history', me) then perform jarvis_deny('history can only be added to'); end if;
    if 'thread' = any(ch) and not jarvis_append_ok(o->'thread', n->'thread', me) then perform jarvis_deny('updates can only be added'); end if;
    if o->>'source' = 'assignment' then
      if not (coalesce(o->'assignees','[]'::jsonb) ? me) then perform jarvis_deny('this isn’t your assignment'); end if;
      if not ch <@ array['status','files','thread','history'] then perform jarvis_deny('only Mr. P can change that'); end if;
      if 'status' = any(ch) and (n->>'status' = 'done' or o->>'status' = 'done') then perform jarvis_deny('only Mr. P marks assignments Done'); end if;
      return;
    end if;
    r := jarvis_role(o->>'projectId', me);
    if r in ('admin','editor') then
      if 'projectId' = any(ch) then
        r2 := jarvis_role(n->>'projectId', me);
        if coalesce(r2,'') not in ('admin','editor') then perform jarvis_deny('you need to be an editor on the other project'); end if;
      end if;
      return;
    end if;
    if coalesce(o->'assignees','[]'::jsonb) ? me and ch <@ array['status','files','thread','history','when'] then return; end if;
    perform jarvis_deny('you can’t change this item');

  elsif tbl = 'assignments' then
    if o is null and n->>'id' = 'aw_' || (n->>'weekStart') and (n->>'weekly')::boolean then return; end if;
    perform jarvis_deny('only Mr. P can change assignments');

  elsif tbl = 'notifs' then
    if o is null and n->>'by' = me then return; end if;
    if o is not null and n is not null and ch <@ array['readBy'] and jarvis_appended(o->'readBy', n->'readBy') is not null
       and not exists(select 1 from jsonb_array_elements_text(jarvis_appended(o->'readBy', n->'readBy')) e where e <> me) then return; end if;
    perform jarvis_deny('notification change not allowed');

  elsif tbl = 'asks' then
    if o is null then
      if n->>'by' is distinct from me or coalesce(jsonb_array_length(n->'replies'),0) > 0 then perform jarvis_deny('asks must be yours'); end if;
      if n->>'kind' = 'lesson' and (n->'plus') is distinct from jsonb_build_array(me) then perform jarvis_deny('bad lesson request'); end if;
      if n->>'kind' = 'merge' and jarvis_role(n->>'projectId', me) is distinct from 'admin' then perform jarvis_deny('only a project admin can ask to combine it'); end if;
      if coalesce(n->>'kind','') not in ('feedback','help','lesson','merge') then perform jarvis_deny('bad ask'); end if;
      return;
    end if;
    if n is null then perform jarvis_deny('asks can’t be deleted'); end if;
    if 'replies' = any(ch) and not jarvis_append_ok(o->'replies', n->'replies', me) then perform jarvis_deny('replies can only be added'); end if;
    if 'plus' = any(ch) and (o->>'kind' <> 'lesson' or not jarvis_toggle_ok(o->'plus', n->'plus', me)) then perform jarvis_deny('you can only +1 for yourself'); end if;
    if o->>'by' = me and ch <@ array['open','note','replies','plus'] then return; end if;
    if o->>'kind' = 'merge' and jarvis_role(o->>'targetId', me) = 'admin' and ch <@ array['open','result','replies'] then return; end if;
    if ch <@ array['replies','plus'] and (o->>'kind' = 'lesson' or jarvis_to_includes(o, me)
        or (o->>'kind' = 'feedback' and (o->>'itemId' is not null and jarvis_can_see_item((select i.data from items i where i.id = o->>'itemId'))))) then return; end if;
    perform jarvis_deny('you can’t change this ask');

  elsif tbl = 'lessons' then
    if o is not null and n is not null and ch <@ array['signups'] and jarvis_toggle_ok(o->'signups', n->'signups', me) then
      if jsonb_array_length(n->'signups') > jsonb_array_length(coalesce(o->'signups','[]'::jsonb)) then
        if jsonb_array_length(n->'signups') > coalesce((o->>'seats')::int, 0) then perform jarvis_deny('that lesson is full'); end if;
      end if;
      return;
    end if;
    perform jarvis_deny('only Mr. P can change lessons');

  elsif tbl = 'polls' then
    if o is not null and n is not null and ch <@ array['responses'] and coalesce((o->>'open')::boolean, false)
       and jarvis_append_ok(o->'responses', n->'responses', me) then return; end if;
    perform jarvis_deny('you can only answer open polls');

  elsif tbl = 'checkins' then
    if n is null then perform jarvis_deny('check-ins can’t be deleted'); end if;
    if n->>'by' = me and n->>'id' = 'ci_' || me || '_' || (n->>'date') and (o is null or o->>'by' = me) then return; end if;
    perform jarvis_deny('that’s not your check-in');

  elsif tbl = 'weeks' then
    if n is null then perform jarvis_deny('weekly reports can’t be deleted'); end if;
    if n->>'by' = me and n->>'id' = 'wk_' || me || '_' || (n->>'weekStart') and (o is null or o->>'by' = me) and not ('days' = any(ch)) then return; end if;
    perform jarvis_deny('that’s not your weekly report');

  elsif tbl = 'settings' then
    k := d->>'id';
    if k = 'profile_' || me then
      if n is null then perform jarvis_deny('profiles can’t be deleted'); end if;
      if 'img' = any(ch) and n->'img' is not null and n->'img' <> 'null'::jsonb then perform jarvis_deny('pictures need Mr. P’s approval'); end if;
      if ch <@ array['id','color','shape','mode','text','imgPending','img','simple','nick','wallName','wantDemo','wantDemoAt'] then return; end if;
      perform jarvis_deny('profile change not allowed');
    end if;
    if k like 'claim\_' || me || '\_%' and d->>'by' = me then
      if n is null then
        if coalesce(o->>'status','planned') in ('planned','returned') then return; end if;
        perform jarvis_deny('counted work can’t be removed');
      end if;
      if coalesce(o->>'status','planned') not in ('planned','returned') and ch <> '{}' then perform jarvis_deny('that’s waiting for Mr. P'); end if;
      if coalesce(n->>'status','planned') not in ('planned','submitted') then perform jarvis_deny('only Mr. P counts work'); end if;
      if ch && array['mp','creditedAt','by','target'] and o is not null then perform jarvis_deny('that can’t be changed'); end if;
      if o is null and (n->>'status' <> 'planned' or n ? 'mp') then perform jarvis_deny('new tags start as planned'); end if;
      return;
    end if;
    if k like 'post\_%' and o is not null and n is not null and coalesce((o->>'published')::boolean,false)
       and ch <@ array['likes'] and jarvis_toggle_ok(coalesce(o->'likes','[]'::jsonb), n->'likes', me) then return; end if;
    perform jarvis_deny('only Mr. P can change that setting');

  elsif tbl = 'events' then
    if o is null then
      if n->>'by' is distinct from me or coalesce(n->>'status','') <> 'pending' then perform jarvis_deny('new events wait for Mr. P’s approval'); end if;
      return;
    end if;
    if o->>'by' is distinct from me or coalesce(o->>'status','') <> 'pending' then perform jarvis_deny('only Mr. P can change this event'); end if;
    if n is null then return; end if;
    if ch && array['status','by','note'] then perform jarvis_deny('only Mr. P approves events'); end if;
    return;

  elsif tbl = 'bank' then
    if o is null then
      if n->>'by' is distinct from me or coalesce(n->>'status','') <> 'raw' then perform jarvis_deny('suggestions go to Mr. P first'); end if;
      return;
    end if;
    if n is null then
      if o->>'by' = me and o->>'status' = 'raw' then return; end if;
      perform jarvis_deny('only a teacher can remove bank cards');
    end if;
    if o->>'by' = me and o->>'status' = 'raw' and not (ch && array['status','by']) then return; end if;
    if o->>'status' = 'ready' and o->>'type' = 'idea' and ch <@ array['starts'] and jarvis_append_ok(o->'starts', n->'starts', me) then return; end if;
    if o->>'status' = 'ready' and o->>'type' = 'request' and ch <@ array['hands'] and jarvis_toggle_ok(o->'hands', n->'hands', me) then return; end if;
    perform jarvis_deny('only a teacher can change bank cards');

  elsif tbl = 'reminders' then
    if o is null then
      if n->>'by' is distinct from me or n->>'to' is distinct from me then perform jarvis_deny('you can only set reminders for yourself'); end if;
      return;
    end if;
    if n is null then
      if o->>'by' = me then return; end if;
      perform jarvis_deny('only the person who set a reminder can delete it');
    end if;
    if o->>'by' = me and not ('by' = any(ch)) and n->>'to' is not distinct from o->>'to' then return; end if;
    if o->>'to' = me and ch <@ array['done','doneAt','when','notified','snoozes'] then return; end if;
    perform jarvis_deny('that reminder belongs to someone else');

  elsif tbl = 'todos' then
    if (o is null or o->>'by' = me) and (n is null or n->>'by' = me) then return; end if;
    perform jarvis_deny('that list belongs to someone else');

  elsif tbl = 'reflections' then
    if (o is not null and o->>'by' is distinct from me) or (n is not null and n->>'by' is distinct from me) then perform jarvis_deny('that reflection belongs to someone else'); end if;
    if n is not null then
      if n->>'kind' is distinct from 'student' then perform jarvis_deny('only teachers can write teacher notes'); end if;
      if n->>'id' is distinct from 'rf_' || (n->>'projectId') || '_' || me then perform jarvis_deny('bad reflection id'); end if;
      if jarvis_role(n->>'projectId', me) is null and not exists(select 1 from items i where i.data->>'projectId' = n->>'projectId' and (i.data->'assignees') ? me) then perform jarvis_deny('you’re not on that project'); end if;
    end if;
    return;

  elsif tbl = 'broadcast' then
    if o is null or n is null then perform jarvis_deny('only a teacher can add or remove broadcast items'); end if;
    if o->>'kind' = 'block' and ch <@ array['who','status','file','text','doneAt','editedBy']
       and (not ('who' = any(ch)) or jarvis_toggle_ok(o->'who', n->'who', me)) then return; end if;
    if o->>'kind' = 'ann' and ch <@ array['who','status','file','doneAt','editedBy']
       and (not ('who' = any(ch)) or jarvis_toggle_ok(o->'who', n->'who', me)) then return; end if;
    if o->>'kind' = 'day' and ch <@ array['tickerExtra','editedBy']
       and jsonb_typeof(coalesce(n->'tickerExtra','[]'::jsonb)) = 'array' and jsonb_array_length(coalesce(n->'tickerExtra','[]'::jsonb)) <= 12
       and length(coalesce(n->>'tickerExtra','')) <= 1600 then return; end if;
    perform jarvis_deny('only a teacher can change that');

  elsif tbl = 'syncs' then
    perform jarvis_deny('only Mr. P can do that');
  else
    perform jarvis_deny('unknown table');
  end if;
end $$;

create or replace function public.jarvis_write(op text, tbl text, rid text, payload jsonb default null, k text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare me text := jarvis_me(); t boolean := jarvis_is_teacher(); o jsonb; n jsonb;
begin
  if me is null then perform jarvis_deny('please sign in'); end if;
  if jarvis_is_wall() then perform jarvis_deny('the Class Wall account can only show the wall'); end if;
  if tbl not in ('projects','assignments','items','notifs','syncs','asks','lessons','polls','checkins','weeks','settings','events','bank','reminders','todos','reflections','broadcast') then perform jarvis_deny('bad table'); end if;
  execute format('select data from public.%I where id = $1 for update', tbl) into o using rid;
  if op = 'put' then n := payload;
  elsif op = 'patch' then n := coalesce(o, '{}'::jsonb) || payload;
  elsif op = 'append' then
    if o is null then perform jarvis_deny('that was deleted'); end if;
    n := jsonb_set(o, array[k], coalesce(o->k, '[]'::jsonb) || payload);
  elsif op = 'delete' then n := null;
  else perform jarvis_deny('bad operation'); end if;
  if n is not null then n := jsonb_set(n, '{id}', to_jsonb(rid)); end if;
  if not t then perform jarvis_check(tbl, o, n, me); end if;
  if n is null then execute format('delete from public.%I where id = $1', tbl) using rid;
  elsif o is null then execute format('insert into public.%I (id, data) values ($1, $2)', tbl) using rid, n;
  else execute format('update public.%I set data = $2, updated_at = now() where id = $1', tbl) using rid, n;
  end if;
  return n;
end $$;
revoke all on function public.jarvis_write(text, text, text, jsonb, text) from public, anon;
grant execute on function public.jarvis_write(text, text, text, jsonb, text) to authenticated;

create or replace function public.jarvis_restore(backup jsonb) returns int
language plpgsql security definer set search_path = public as $$
declare t text; n int := 0; rj jsonb;
begin
  if not jarvis_is_teacher() then perform jarvis_deny('only Mr. P can restore'); end if;
  foreach t in array array['projects','assignments','items','notifs','syncs','asks','lessons','polls','checkins','weeks','settings','events','bank','reflections','broadcast'] loop
    if not (backup ? t) then continue; end if;
    execute format('delete from public.%I', t);
    for rj in select value from jsonb_array_elements(coalesce(backup->t, '[]'::jsonb)) loop
      if rj->>'id' is not null then
        execute format('insert into public.%I (id, data) values ($1, $2) on conflict (id) do update set data = excluded.data', t) using rj->>'id', rj;
        n := n + 1;
      end if;
    end loop;
  end loop;
  return n;
end $$;
revoke all on function public.jarvis_restore(jsonb) from public, anon;
grant execute on function public.jarvis_restore(jsonb) to authenticated;

create or replace function public.jarvis_merge(p_id text, t_id text, mode text, ask_id text default null) returns text
language plpgsql security definer set search_path = public as $$
declare me text := jarvis_me(); pd jsonb; td jsonb; a jsonb; ok boolean := false; st jsonb := jarvis_stamp(); nid text; status text; r record;
begin
  if me is null then perform jarvis_deny('please sign in'); end if;
  select data into pd from projects where id = p_id for update;
  select data into td from projects where id = t_id for update;
  if pd is null or td is null or p_id = t_id then perform jarvis_deny('project not found'); end if;
  if mode not in ('nest','convert') then perform jarvis_deny('bad mode'); end if;
  if jarvis_is_teacher() then ok := true;
  elsif jarvis_role(p_id, me) = 'admin' and jarvis_role(t_id, me) = 'admin' then ok := true;
  elsif ask_id is not null and jarvis_role(t_id, me) = 'admin' then
    select data into a from asks where id = ask_id;
    ok := a is not null and a->>'kind' = 'merge' and coalesce((a->>'open')::boolean,false) and a->>'projectId' = p_id and a->>'targetId' = t_id and a->>'mode' = mode
          and jarvis_role(p_id, a->>'by') = 'admin';
  end if;
  if not ok then perform jarvis_deny('you can’t combine these projects'); end if;
  if coalesce(td->>'parentId','') <> '' then perform jarvis_deny('the bigger project is already inside another'); end if;
  if exists(select 1 from projects where data->>'parentId' = p_id) then perform jarvis_deny('take the projects inside it out first'); end if;

  if mode = 'nest' then
    update projects set data = jsonb_set(data, '{parentId}', to_jsonb(t_id)) || jsonb_build_object('thread', coalesce(data->'thread','[]'::jsonb) ||
      jsonb_build_array(jsonb_build_object('id','u'||substr(md5(random()::text),1,10),'by',me,'text','Moved inside “'||(td->>'name')||'”','sys',true) || st)), updated_at = now() where id = p_id;
    update projects set data = data || jsonb_build_object('thread', coalesce(data->'thread','[]'::jsonb) ||
      jsonb_build_array(jsonb_build_object('id','u'||substr(md5(random()::text),1,10),'by',me,'text','“'||(pd->>'name')||'” is now part of this project','sys',true) || st)), updated_at = now() where id = t_id;
    nid := null;
  else
    select case when count(*) > 0 and bool_and(data->>'status' in ('done','sub')) then 'done' when bool_or(data->>'status' <> 'not') then 'work' else 'not' end
      into status from items where data->>'projectId' = p_id;
    nid := 'i' || substr(md5(random()::text), 1, 12);
    insert into items (id, data) values (nid, jsonb_build_object(
      'id', nid, 'source','task', 'title', pd->>'name', 'description', coalesce(pd->>'description',''),
      'assignees', coalesce((select jsonb_agg(key) from jsonb_each_text(coalesce(pd->'roles','{}'::jsonb)) where value <> 'viewer' and key <> 't'), '[]'::jsonb),
      'status', coalesce(status,'not'), 'due','', 'priority','med', 'projectId', t_id, 'parentId', null,
      'files', coalesce(pd->'files','[]'::jsonb), 'thread', coalesce(pd->'thread','[]'::jsonb),
      'history', jsonb_build_array(jsonb_build_object('kind','converted','by',me,'from',pd->>'name') || st)));
    -- everything moves over; top-level items go under the new item, deeper layers keep their place
    update items set data = data || jsonb_build_object('projectId', t_id,
        'history', coalesce(data->'history','[]'::jsonb) || jsonb_build_array(jsonb_build_object('kind','moved','by',me,'from',pd->>'name','to',td->>'name') || st))
      || case when coalesce(data->>'parentId','') = '' then jsonb_build_object('parentId', nid) else '{}'::jsonb end,
      updated_at = now()
      where data->>'projectId' = p_id and id <> nid;
    -- people from the smaller project join the bigger one
    update projects set data = jsonb_set(data, '{roles}', coalesce((select jsonb_object_agg(key, case when value = 'viewer' then 'viewer' else 'editor' end) from jsonb_each_text(coalesce(pd->'roles','{}'::jsonb))), '{}'::jsonb) || coalesce(data->'roles','{}'::jsonb))
      || jsonb_build_object('thread', coalesce(data->'thread','[]'::jsonb) || jsonb_build_array(jsonb_build_object('id','u'||substr(md5(random()::text),1,10),'by',me,'text','“'||(pd->>'name')||'” was turned into an item in this project','sys',true) || st)),
      updated_at = now() where id = t_id;
    update asks set data = data || jsonb_build_object('projectId', t_id, 'itemId', coalesce(data->>'itemId', nid)), updated_at = now() where data->>'projectId' = p_id and data->>'kind' <> 'merge';
    update asks set data = data || jsonb_build_object('open', false), updated_at = now() where data->>'kind' = 'merge' and (data->>'projectId' = p_id or data->>'targetId' = p_id) and coalesce(id,'') <> coalesce(ask_id,'');
    update checkins set data = jsonb_set(data, '{active}', (select coalesce(jsonb_agg(case when e = to_jsonb('p:'||p_id) then to_jsonb('i:'||nid) else e end), '[]'::jsonb) from jsonb_array_elements(coalesce(data->'active','[]'::jsonb)) e)), updated_at = now()
      where data->'active' ? ('p:'||p_id);
    update projects set data = data || jsonb_build_object('parentId', null), updated_at = now() where data->>'parentId' = p_id;
    delete from projects where id = p_id;
  end if;
  if ask_id is not null then
    update asks set data = data || jsonb_build_object('open', false, 'result', 'approved'), updated_at = now() where id = ask_id;
  end if;
  return nid;
end $$;
revoke all on function public.jarvis_merge(text, text, text, text) from public, anon;
grant execute on function public.jarvis_merge(text, text, text, text) to authenticated;
revoke execute on function public.jarvis_check(text, jsonb, jsonb, text) from public, anon, authenticated;


create table if not exists public.contacts (
  pid text primary key,
  email text not null,
  updated_at timestamptz not null default now()
);
alter table public.contacts enable row level security;
revoke all on public.contacts from anon, authenticated;
grant select on public.contacts to authenticated;
drop policy if exists "jarvis read" on public.contacts;
create policy "jarvis read" on public.contacts for select to authenticated using (jarvis_is_teacher() or pid = jarvis_me());

create or replace function public.jarvis_set_email(p_email text, p_pid text default null) returns text
language plpgsql security definer set search_path = public as $$
declare me text := jarvis_me(); who text := coalesce(nullif(p_pid,''), jarvis_me()); e text := lower(trim(coalesce(p_email,'')));
begin
  if me is null or jarvis_is_wall() then perform jarvis_deny('please sign in'); end if;
  if who <> me and not jarvis_is_teacher() then perform jarvis_deny('you can only set your own email'); end if;
  if not exists(select 1 from people where pid = who) then perform jarvis_deny('student not found'); end if;
  if e = '' then delete from contacts where pid = who; return null; end if;
  if e !~ '^[a-z0-9._%+-]+@([a-z0-9-]+\.)*ytech\.edu$' then perform jarvis_deny('use your school email (ending in ytech.edu)'); end if;
  insert into contacts (pid, email, updated_at) values (who, e, now())
    on conflict (pid) do update set email = excluded.email, updated_at = now();
  return e;
end $$;
revoke all on function public.jarvis_set_email(text, text) from public, anon;
grant execute on function public.jarvis_set_email(text, text) to authenticated;

create table if not exists public.jarvis_secrets (name text primary key, value text not null);
alter table public.jarvis_secrets enable row level security;
revoke all on public.jarvis_secrets from anon, authenticated;
insert into public.jarvis_secrets (name, value) values ('outbox', md5(random()::text || clock_timestamp()::text) || md5(random()::text))
  on conflict (name) do nothing;
create table if not exists public.sent_log (key text primary key, sent_at timestamptz not null default now());
alter table public.sent_log enable row level security;
revoke all on public.sent_log from anon, authenticated;

create or replace function public.jarvis_senior_year() returns int
language sql stable as $$
  select (extract(year from d) + case when extract(month from d) >= 7 then 1 else 0 end)::int
  from (select (now() at time zone 'America/New_York')::date d) x
$$;


-- 2.0: students can opt out of automatic emails (Edit my profile)
alter table public.contacts add column if not exists optout boolean not null default false;
create or replace function public.jarvis_set_optout(p_on boolean, p_pid text default null) returns boolean
language plpgsql security definer set search_path = public as $$
declare me text := jarvis_me(); who text := coalesce(nullif(p_pid,''), jarvis_me());
begin
  if me is null then perform jarvis_deny('please sign in'); end if;
  if who <> me and not jarvis_is_teacher() then perform jarvis_deny('you can only change your own email setting'); end if;
  update contacts set optout = coalesce(p_on,false), updated_at = now() where pid = who;
  return coalesce(p_on,false);
end $$;
revoke all on function public.jarvis_set_optout(boolean, text) from public, anon;
grant execute on function public.jarvis_set_optout(boolean, text) to authenticated;

create or replace function public.jarvis_outbox(p_secret text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  out jsonb := '[]'::jsonb;
  tz text := 'America/New_York';
  lnow timestamp := now() at time zone tz;
  today date := (now() at time zone tz)::date;
  nextday date;
  r record;
begin
  if p_secret is null or p_secret <> (select value from jarvis_secrets where name = 'outbox') then raise exception 'not allowed'; end if;
  nextday := today + 1;
  if extract(dow from nextday) = 6 then nextday := nextday + 2; elsif extract(dow from nextday) = 0 then nextday := nextday + 1; end if;
  for r in
    select rm.id, rm.data d, c.email, p.name
    from reminders rm join people p on p.pid = rm.data->>'to' and p.role = 'student' and p.active and coalesce(p.grad,0) < jarvis_senior_year() + 2
    join contacts c on c.pid = p.pid and not coalesce(c.optout,false)
    where coalesce((rm.data->>'done')::boolean,false) = false
      and (rm.data->>'when')::bigint <= (extract(epoch from now())*1000)::bigint
      and (rm.data->>'when')::bigint >= (extract(epoch from now() - interval '2 days')*1000)::bigint
      and not exists (select 1 from sent_log s where s.key = 'rem:' || rm.id || ':' || (rm.data->>'when'))
  loop
    out := out || jsonb_build_array(jsonb_build_object('type','email','key','rem:' || r.id || ':' || (r.d->>'when'),'to',r.email,
      'subject','Reminder: ' || coalesce(r.d->>'label','JARVIS'),
      'text','Hi ' || split_part(r.name,' ',1) || ',' || chr(10) || chr(10) || 'Reminder: ' || coalesce(r.d->>'label','') ||
        case when coalesce(r.d->>'note','') <> '' then chr(10) || '"' || (r.d->>'note') || '"' else '' end ||
        chr(10) || chr(10) || 'Open JARVIS to see it: https://ycstcommtech.github.io/ProjectManagementSystem/'));
  end loop;
  if lnow::time >= time '14:30' then
    for r in
      select i.id, i.data d, a.data ad, c.email, p.name
      from items i join assignments a on a.id = i.data->>'assignmentId'
      join people p on p.pid = i.data->'assignees'->>0 and p.role = 'student' and p.active and coalesce(p.grad,0) < jarvis_senior_year() + 2
      join contacts c on c.pid = p.pid and not coalesce(c.optout,false)
      where i.data->>'source' = 'assignment' and coalesce((a.data->>'weekly')::boolean,false) = false
        and i.data->>'due' = nextday::text and coalesce(i.data->>'status','not') not in ('sub','done')
        and not exists (select 1 from sent_log s where s.key = 'due:' || i.id || ':' || (i.data->>'due'))
    loop
      out := out || jsonb_build_array(jsonb_build_object('type','email','key','due:' || r.id || ':' || (r.d->>'due'),'to',r.email,
        'subject','Due ' || to_char(nextday,'FMDay') || ': ' || coalesce(r.ad->>'title', r.d->>'title'),
        'text','Hi ' || split_part(r.name,' ',1) || ',' || chr(10) || chr(10) || '"' || coalesce(r.ad->>'title', r.d->>'title') || '" is due ' || to_char(nextday,'FMDay, FMMonth FMDD') ||
          ' and JARVIS doesn''t show it turned in yet.' || chr(10) || chr(10) || 'Add your link and set it to Submitted: https://ycstcommtech.github.io/ProjectManagementSystem/'));
    end loop;
  end if;
  for r in
    select l.id, l.data d, s.pid, c.email
    from lessons l cross join lateral jsonb_array_elements_text(coalesce(l.data->'signups','[]'::jsonb)) s(pid)
    join people p on p.pid = s.pid and p.role = 'student' and p.active and coalesce(p.grad,0) < jarvis_senior_year() + 2
    join contacts c on c.pid = s.pid and not coalesce(c.optout,false)
    where (l.data->>'date')::date >= today
      and not exists (select 1 from sent_log x where x.key = 'les:' || l.id || ':' || s.pid)
  loop
    out := out || jsonb_build_array(jsonb_build_object('type','event','key','les:' || r.id || ':' || r.pid,'to',r.email,
      'title','Lesson: ' || coalesce(r.d->>'title','Comm Tech lesson'),
      'start',(r.d->>'date') || 'T' || coalesce(nullif(r.d->>'start',''),'09:00') || ':00',
      'end',(r.d->>'date') || 'T' || coalesce(nullif(r.d->>'end',''), nullif(r.d->>'start',''),'09:30') || ':00',
      'desc','You signed up for this lesson in JARVIS.'));
  end loop;
  for r in
    select b.id, b.data d, w.pid, c.email
    from broadcast b cross join lateral jsonb_array_elements_text(coalesce(b.data->'who','[]'::jsonb)) w(pid)
    join people p on p.pid = w.pid and p.role = 'student' and p.active and coalesce(p.grad,0) < jarvis_senior_year() + 2
    join contacts c on c.pid = w.pid and not coalesce(c.optout,false)
    where b.data->>'kind' in ('block','ann')
      and coalesce(b.data->>'date', b.data->>'start') >= today::text
      and not exists (select 1 from sent_log x where x.key = 'tv:' || b.id || ':' || w.pid)
  loop
    out := out || jsonb_build_array(jsonb_build_object('type','event','key','tv:' || r.id || ':' || r.pid,'to',r.email,
      'start', coalesce(r.d->>'date', r.d->>'start') || 'T07:45:00',
      'end', coalesce(r.d->>'date', r.d->>'start') || 'T08:20:00',
      'title','Spartan TV: ' || case when r.d->>'kind' = 'ann' then coalesce(r.d->>'title','announcement') || ' graphic' else coalesce(r.d->>'name','segment') end || ' (yours)',
      'desc','Spartan TV streams 7:45–8:20 AM. You claimed this in JARVIS → Spartan TV, so have it ready before the broadcast.'));
  end loop;

  -- 2.0: safety alerts. When JARVIS Assistant marks a chat urgent, email the teacher (ai_config.alertEmail).
  for r in
    select a.id, a.data d, p.name, lower(trim((select data->>'alertEmail' from settings where id = 'ai_config'))) em
    from asks a join people p on p.pid = a.data->>'by'
    where coalesce((a.data->>'urgent')::boolean,false)
      and coalesce(a.data->>'sentAt',a.data->>'ts','0')::bigint >= (extract(epoch from now() - interval '3 days')*1000)::bigint
      and not exists (select 1 from sent_log x where x.key = 'alert:' || a.id)
  loop
    continue when coalesce(r.em,'') !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$';
    out := out || jsonb_build_array(jsonb_build_object('type','email','key','alert:' || r.id,'to',r.em,
      'subject','URGENT (JARVIS): possible safety concern from ' || split_part(r.name,' ',1),
      'text','JARVIS Assistant flagged a conversation with ' || r.name || ' as a possible safety concern (self-harm, harm to others, abuse, or being unsafe).' || chr(10) || chr(10) ||
        'Please check on the student and follow the school''s procedures. Open the conversation in JARVIS > Asks: ' || coalesce((select value from jarvis_secrets where name = 'site'), '') || chr(10) || chr(10) ||
        'This email does not include what the student wrote, for privacy.'));
  end loop;
  return out;
end $$;
revoke all on function public.jarvis_outbox(text) from public;
grant execute on function public.jarvis_outbox(text) to anon, authenticated;

create or replace function public.jarvis_outbox_done(p_secret text, p_keys text[]) returns int
language plpgsql security definer set search_path = public as $$
begin
  if p_secret is null or p_secret <> (select value from jarvis_secrets where name = 'outbox') then raise exception 'not allowed'; end if;
  insert into sent_log (key) select unnest(p_keys) on conflict do nothing;
  return coalesce(array_length(p_keys,1),0);
end $$;
revoke all on function public.jarvis_outbox_done(text, text[]) from public;
grant execute on function public.jarvis_outbox_done(text, text[]) to anon, authenticated;

drop policy if exists "jarvis read" on public.settings;
create policy "jarvis read" on public.settings for select to authenticated using (
  jarvis_is_teacher() or id like 'profile\_%' or id like 'week\_%' or id = 'mp_config'
  or (id like 'claim\_%' and data->>'by' = jarvis_me())
  or (id like 'post\_%' and coalesce((data->>'published')::boolean, false))
  or (jarvis_is_helper() and (id like 'post\_%' or id = 'wall_cfg' or (id like 'alog\_%' and data->>'by' = jarvis_me()))));

do $$
declare t text;
begin
  foreach t in array array['people','contacts','projects','assignments','items','notifs','syncs','asks','lessons','polls','checkins','weeks','settings','events','bank','reminders','todos','reflections','broadcast'] loop
    execute format('drop policy if exists "no wall" on public.%I', t);
    execute format('create policy "no wall" on public.%I as restrictive for select to authenticated using (not jarvis_is_wall())', t);
  end loop;
end $$;

create or replace function public.jarvis_am_wall() returns boolean
language sql stable security definer set search_path = public as $$
  select jarvis_is_wall()
$$;
revoke all on function public.jarvis_am_wall() from public, anon;
grant execute on function public.jarvis_am_wall() to authenticated;

create or replace function public.jarvis_wall() returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare
  cfg jsonb := coalesce((select data from settings where id = 'wall_cfg'), '{}'::jsonb);
  nextonly boolean := coalesce(cfg->>'mode','full') = 'next';
  off jsonb := coalesce(cfg->'off','[]'::jsonb);
  since bigint := (extract(epoch from now() - interval '3 days')*1000)::bigint;
  demo_since bigint := (extract(epoch from now() - interval '5 days')*1000)::bigint;
  useuser boolean := coalesce((cfg->>'useUser')::boolean, true);
  useci boolean := coalesce((cfg->>'useCheckin')::boolean, true);
  today text := ((now() at time zone 'America/New_York')::date)::text;
  cutover time := coalesce(nullif(cfg->>'cutover','')::time, time '09:55');
  showtoday boolean := (now() at time zone 'America/New_York')::time >= cutover;
  out jsonb := '[]'::jsonb;
  r record; pj jsonb; nx jsonb; fin jsonb; fin_any boolean; k int := 0; ci jsonb; working text;
begin
  if not (jarvis_is_wall() or jarvis_is_teacher() or jarvis_is_helper()) then raise exception 'not allowed'; end if;
  for r in
    select p.pid, p.grad, p.username, pr.data prof
    from people p left join settings pr on pr.id = 'profile_' || p.pid
    where p.role = 'student' and p.active and not (off ? coalesce(p.grad::text,'')) and not (coalesce(cfg->'hide','[]'::jsonb) ? p.pid)
    order by p.grad nulls last, lower(coalesce(nullif(trim(pr.data->>'wallName'),''), p.username)), p.pid
  loop
    k := k + 1;
    select pp.data into pj from projects pp
      where coalesce((pp.data->>'onWall')::boolean,false) and pp.data->'roles' ? r.pid
        and not coalesce((pp.data->>'completed')::boolean,false) and coalesce(pp.data->>'deletedAt','') = ''
      order by (pp.data->>'nextDate') nulls last, pp.updated_at desc limit 1;
    nx := pj;
    if nx is null or coalesce(nx->>'nextStep','') = '' then
      select pp.data into nx from projects pp
        where pp.data->'roles' ? r.pid and not coalesce((pp.data->>'completed')::boolean,false)
          and coalesce(trim(pp.data->>'nextStep'),'') <> ''
        order by (pp.data->>'nextDate') nulls last, pp.updated_at desc limit 1;
      if nx is null then nx := pj; end if;
    end if;
    working := null; ci := null;
    if useci then
      if showtoday then
        select c.data into ci from checkins c where c.id = 'ci_' || r.pid || '_' || today;
      else
        select c.data into ci from checkins c where c.data->>'by' = r.pid and c.data->>'date' < today
          and not coalesce((c.data->>'absent')::boolean,false)
          order by c.data->>'date' desc limit 1;
      end if;
      if ci is not null and not nextonly then
        select string_agg(coalesce(pp.data->>'name', ii.data->>'title'), ', ') into working
        from jsonb_array_elements_text(coalesce(ci->'active','[]'::jsonb)) a(k)
        left join projects pp on a.k = 'p:' || pp.id
        left join items ii on a.k = 'i:' || ii.id
        where coalesce(pp.data->>'name', ii.data->>'title') is not null;
      end if;
    end if;
    fin := null; fin_any := false;
    if not nextonly then
      select pp.data into fin from projects pp
        where pp.data->'roles' ? r.pid
          and coalesce((pp.data->>'completed')::boolean,false) and coalesce((pp.data->>'completedAt')::bigint,0) >= since
        order by (pp.data->>'completedAt')::bigint desc limit 1;
      if fin is null then
        select exists(select 1 from items i cross join lateral jsonb_array_elements(coalesce(i.data->'history','[]'::jsonb)) h
          where i.data->>'source' = 'task' and i.data->'assignees' ? r.pid and i.data->>'status' = 'done'
            and h->>'kind' = 'status' and h->>'to' = 'done' and coalesce((h->>'ts')::bigint,0) >= since) into fin_any;
      end if;
    end if;
    out := out || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
      'name', coalesce(nullif(left(trim(r.prof->>'wallName'),24),''), case when useuser then r.username end, 'Creator ' || k),
      'grad', r.grad,
      'blurb', case when nextonly then null else nullif(left(working,90),'') end,
      'next', nullif(left(trim(regexp_replace(coalesce(ci->>'line',''), '\s+', ' ', 'g')),110),''),
      'finished', case when fin is not null then coalesce(nullif(left(trim(fin->>'name'),70),''),'a project') when fin_any then 'a step' else null end,
      'demo', case when not nextonly and coalesce((r.prof->>'wantDemoAt')::bigint,0) >= demo_since then nullif(left(trim(r.prof->>'wantDemo'),50),'') else null end
    )));
  end loop;
  return jsonb_build_object('mode', case when nextonly then 'next' else 'full' end, 'rows', out, 'showing', case when showtoday then 'today' else 'last' end, 'cutover', to_char(cutover,'FMHH12:MI AM'), 'at', (extract(epoch from now())*1000)::bigint);
end $$;
revoke all on function public.jarvis_wall() from public, anon;
grant execute on function public.jarvis_wall() to authenticated;

insert into public.people (id, pid, username, name, role)
select id, 'wall', 'wall', 'Class Wall', 'wall' from auth.users where email = 'wall@jarvis.local'
on conflict (pid) do nothing;

create or replace function public.jarvis_ticker() returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce((
    select jsonb_build_object(
      'lines', coalesce(b.data->'days'->(((now() at time zone 'America/New_York')::date)::text), '[]'::jsonb)
             || coalesce((select dd.data->'tickerExtra' from broadcast dd where dd.id = 'tvd_' || (((now() at time zone 'America/New_York')::date)::text)), '[]'::jsonb),
      'style', coalesce(b.data->'style', '{}'::jsonb),
      't', coalesce(b.data->'pubAt', '0'::jsonb))
    from broadcast b where b.id = 'tv_ticker'), jsonb_build_object('lines','[]'::jsonb,'style','{}'::jsonb,'t',0))
$$;


do $$
declare f record; had boolean;
begin
  for f in select p.oid, p.oid::regprocedure::text sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname like 'jarvis%' loop
    had := has_function_privilege('authenticated', f.oid, 'execute');
    execute format('revoke execute on function %s from public, anon', f.sig);
    if had then execute format('grant execute on function %s to authenticated', f.sig); end if;
  end loop;
  grant execute on function public.jarvis_outbox(text) to anon;
  grant execute on function public.jarvis_outbox_done(text, text[]) to anon;
  grant execute on function public.jarvis_ticker() to anon, authenticated;
end $$;


update public.people set helper = true where username = 'robert' and role = 'student';

select (select count(*) from people where helper) as student_assistants, (select count(*) from people where role = 'wall') as wall_accounts, (select value from public.jarvis_secrets where name = 'outbox') as secret;
select (select count(*) from people where helper) as student_assistants, (select count(*) from people where role = 'wall') as wall_accounts, (select value from public.jarvis_secrets where name = 'outbox') as secret;
-- ===== Sandbox-only safety: emails go ONLY to addresses on the allow list =====
create table if not exists public.jarvis_allow (email text primary key);
alter table public.jarvis_allow enable row level security;
revoke all on public.jarvis_allow from anon, authenticated;

create or replace function public.jarvis_set_email(p_email text, p_pid text default null) returns text
language plpgsql security definer set search_path = public as $$
declare me text := jarvis_me(); who text := coalesce(nullif(p_pid,''), jarvis_me()); e text := lower(trim(coalesce(p_email,'')));
begin
  if me is null then perform jarvis_deny('please sign in'); end if;
  if who <> me and not jarvis_is_teacher() then perform jarvis_deny('you can only set your own email'); end if;
  if not exists(select 1 from people where pid = who) then perform jarvis_deny('student not found'); end if;
  if e = '' then delete from contacts where pid = who; return null; end if;
  if not exists(select 1 from jarvis_allow where lower(email) = e) then perform jarvis_deny('in the sandbox, only emails on the allow list can be saved'); end if;
  insert into contacts (pid, email, updated_at) values (who, e, now())
    on conflict (pid) do update set email = excluded.email, updated_at = now();
  return e;
end $$;
revoke all on function public.jarvis_set_email(text, text) from public, anon;
grant execute on function public.jarvis_set_email(text, text) to authenticated;

-- Wrap the real outbox so anything not on the allow list is dropped (belt and braces)
do $$ begin
  -- On a re-run, the main file just rebuilt jarvis_outbox fresh, so swap it in again.
  drop function if exists public.jarvis_outbox_all(text);
  alter function public.jarvis_outbox(text) rename to jarvis_outbox_all;
end $$;
revoke all on function public.jarvis_outbox_all(text) from public, anon, authenticated;
create or replace function public.jarvis_outbox(p_secret text) returns jsonb
language sql security definer set search_path = public as $$
  select coalesce(jsonb_agg(x), '[]'::jsonb) from jsonb_array_elements(jarvis_outbox_all(p_secret)) x
  where lower(coalesce(x->>'to','')) in (select lower(email) from jarvis_allow);
$$;
revoke all on function public.jarvis_outbox(text) from public;
grant execute on function public.jarvis_outbox(text) to anon, authenticated;

-- JARVIS Assistant starts ON in the sandbox
insert into public.settings (id, data) values ('ai_config', '{"id":"ai_config","enabled":true,"teacherName":"Mr. P","alertEmail":"cpavlovich@ytech.edu","hints":true,"limit":25,"urgentAlert":true,"context":"York Tech Communication Technology. Majors: video, photography, graphic design, animation, web, printing. Students run the Spartan TV morning show."}')
  on conflict (id) do nothing;

select 'JARVIS 2.0 sandbox is set up. Now run file 2.' as done;
