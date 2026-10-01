-- ŠÚDOLSKÉ ŠÍPKY — schvaľovanie nových hráčov + galéria

-- ══════════════════════════════════════════
-- SCHVAĽOVANIE NOVÝCH HRÁČOV
-- ══════════════════════════════════════════
alter table players add column if not exists approved boolean not null default false;

-- existujúci hráči (registrovaní pred touto zmenou) sa automaticky považujú za schválených
update players set approved = true where approved = false;

create or replace function login_player(p_name text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_hash text;
  v_approved boolean;
begin
  select password_hash, approved into v_hash, v_approved from players where name = trim(p_name);
  if v_hash is null or v_hash <> crypt(p_password, v_hash) then
    return jsonb_build_object('status','error','message','Nesprávne meno alebo heslo.');
  end if;
  if not v_approved then
    return jsonb_build_object('status','error','message','Váš účet ešte nie je schválený. Požiadajte niektorého z existujúcich hráčov, nech vás schváli po prihlásení (tlačidlo „⏳ Schváliť" v hlavičke).');
  end if;
  return jsonb_build_object('status','ok');
end;
$$;

create or replace function register_player(p_name text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if p_name is null or trim(p_name) = '' then
    return jsonb_build_object('status','error','message','Chýba meno.');
  end if;
  if p_password is null or length(p_password) < 4 then
    return jsonb_build_object('status','error','message','Heslo musí mať aspoň 4 znaky.');
  end if;
  begin
    insert into players(name, password_hash) values (trim(p_name), crypt(p_password, gen_salt('bf')));
  exception when unique_violation then
    return jsonb_build_object('status','error','message','Meno je obsadené.');
  end;
  return jsonb_build_object('status','ok','message','Registrácia úspešná. Počkajte, kým vás schváli niektorý z existujúcich hráčov — potom sa budete môcť prihlásiť.');
end;
$$;

-- zoznam hráčov čakajúcich na schválenie (bez hesla, bezpečné pre anon)
create or replace view players_pending as
  select id, name, created_at from players where approved = false order by created_at;

grant select on players_pending to anon;

-- schválenie nového hráča existujúcim (overeným) hráčom cez jeho vlastné heslo
create or replace function approve_player(p_approver_name text, p_approver_password text, p_target_name text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_hash text;
  v_approver_approved boolean;
  v_target_approved boolean;
begin
  select password_hash, approved into v_hash, v_approver_approved from players where name = trim(p_approver_name);
  if v_hash is null or v_hash <> crypt(p_approver_password, v_hash) then
    return jsonb_build_object('status','error','message','Nesprávne heslo.');
  end if;
  if not v_approver_approved then
    return jsonb_build_object('status','error','message','Váš účet ešte nie je schválený, preto nemôžete schvaľovať iných.');
  end if;

  select approved into v_target_approved from players where name = trim(p_target_name);
  if v_target_approved is null then
    return jsonb_build_object('status','error','message','Hráč neexistuje.');
  end if;
  if v_target_approved then
    return jsonb_build_object('status','error','message','Tento hráč je už schválený.');
  end if;

  update players set approved = true where name = trim(p_target_name);
  return jsonb_build_object('status','ok');
end;
$$;

grant execute on function login_player(text, text) to anon;
grant execute on function register_player(text, text) to anon;
grant execute on function approve_player(text, text, text) to anon;

-- ══════════════════════════════════════════
-- GALÉRIA
-- ══════════════════════════════════════════
create table if not exists gallery_items (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  file_url text not null,
  file_type text not null check (file_type in ('image','video')),
  caption text,
  uploader_name text
);

alter table gallery_items enable row level security;

drop policy if exists "public read" on gallery_items;
create policy "public read" on gallery_items for select using (true);

drop policy if exists "public insert" on gallery_items;
create policy "public insert" on gallery_items for insert with check (true);

drop policy if exists "public delete" on gallery_items;
create policy "public delete" on gallery_items for delete using (true);

insert into storage.buckets (id, name, public)
values ('gallery', 'gallery', true)
on conflict (id) do nothing;

drop policy if exists "gallery_public_read" on storage.objects;
create policy "gallery_public_read" on storage.objects
  for select to anon using (bucket_id = 'gallery');

drop policy if exists "gallery_anon_upload" on storage.objects;
create policy "gallery_anon_upload" on storage.objects
  for insert to anon with check (bucket_id = 'gallery');

drop policy if exists "gallery_anon_delete" on storage.objects;
create policy "gallery_anon_delete" on storage.objects
  for delete to anon using (bucket_id = 'gallery');

notify pgrst, 'reload schema';
