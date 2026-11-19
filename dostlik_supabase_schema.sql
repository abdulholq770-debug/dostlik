-- =====================================================================
-- DOSTLIK · Supabase sxemasi (1-bosqich)
-- Supabase -> SQL Editor -> New query -> butun faylni qo'yib RUN bosing.
-- =====================================================================
create extension if not exists pgcrypto;

create type user_role     as enum ('dev','big','staff','user');
create type branch_status as enum ('pending','active','blocked');

-- ---------- Mamlakatlar (neighbors = yaqinlik tartibida) ----------
create table countries (
  code text primary key,
  name_uz text not null,
  neighbors text[] not null default '{}'
);
insert into countries values
 ('UZ','Oʻzbekiston','{KZ,KG,TJ,TM,AF}'),
 ('KZ','Qozogʻiston','{KG,UZ,RU,TM}'),
 ('KG','Qirgʻiziston','{KZ,UZ,TJ}'),
 ('TJ','Tojikiston','{UZ,KG,AF}'),
 ('TM','Turkmaniston','{UZ,AF,KZ}'),
 ('AF','Afgʻoniston','{TJ,UZ,TM}'),
 ('RU','Rossiya','{KZ,UZ}');

-- ---------- Filiallar ----------
create table branches (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  country_code text not null references countries(code),
  region text not null,
  district text not null,
  address text not null,
  lat double precision, lng double precision,
  owner_name text not null,
  owner_phone text not null check (owner_phone ~ '^\+[1-9][0-9]{8,14}$'),
  branch_phone text check (branch_phone ~ '^\+[1-9][0-9]{8,14}$'),
  work_hours text,
  tax_id text not null,
  doc_url text,
  status branch_status not null default 'pending',
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now(),
  unique (country_code, region, district, name)
);

-- ---------- Profillar ----------
create table profiles (
  id uuid primary key references auth.users on delete cascade,
  username text not null check (username ~ '^[a-z0-9_]{3,24}$'),
  phone text not null check (phone ~ '^\+[1-9][0-9]{8,14}$'),
  role user_role not null default 'user',
  branch_id uuid references branches(id),
  country_code text references countries(code),
  country_changed_at timestamptz,
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create unique index profiles_username_uq on profiles (lower(username));
create unique index profiles_phone_uq    on profiles (phone);
create unique index profiles_one_dev     on profiles (role) where role = 'dev';  -- faqat BITTA dasturchi

-- ---------- Takliflar (telefon orqali admin qo'shish) ----------
create table invites (
  id uuid primary key default gen_random_uuid(),
  phone text not null check (phone ~ '^\+[1-9][0-9]{8,14}$'),
  role user_role not null check (role in ('big','staff')),
  branch_id uuid not null references branches(id),
  created_by uuid not null,
  created_at timestamptz not null default now(),
  used_at timestamptz
);
create unique index invites_open_phone on invites (phone) where used_at is null;

-- ---------- Mahsulotlar ----------
create table products (
  id uuid primary key default gen_random_uuid(),
  branch_id uuid not null references branches(id) on delete cascade,
  country_code text not null references countries(code),
  name text not null,
  description text,
  price numeric(14,2) not null check (price >= 0),
  stock int not null default 0 check (stock >= 0),
  image_url text,
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create index products_country on products (country_code) where active;

-- ---------- Jurnal ----------
create table audit_log (
  id bigint generated always as identity primary key,
  actor uuid, action text not null, details jsonb, at timestamptz not null default now()
);

-- ---------- Dasturchi uchun bir martalik maxfiy kod ----------
create table private_setup (id int primary key default 1 check (id = 1), code_hash text not null);

-- =====================================================================
-- YORDAMCHI FUNKSIYALAR
-- =====================================================================
create function me_role() returns user_role language sql stable security definer set search_path = public as
$$ select role from profiles where id = auth.uid() and active $$;

create function me_branch() returns uuid language sql stable security definer set search_path = public as
$$ select branch_id from profiles where id = auth.uid() and active $$;

create function log_action(a text, d jsonb) returns void language sql security definer set search_path = public as
$$ insert into audit_log(actor, action, details) values (auth.uid(), a, d) $$;
revoke execute on function log_action(text, jsonb) from public, anon, authenticated;

-- =====================================================================
-- RO'YXATDAN O'TISH TRIGGERI (rol HECH QACHON mijozdan olinmaydi)
-- =====================================================================
create function handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_user  text := lower(coalesce(new.raw_user_meta_data->>'username',''));
  v_phone text := '+' || regexp_replace(coalesce(new.phone,''), '\D', '', 'g');
  v_cc    text := upper(nullif(new.raw_user_meta_data->>'country',''));
  v_role  user_role := 'user';
  v_branch uuid;
  inv invites%rowtype;
begin
  if v_user !~ '^[a-z0-9_]{3,24}$' then raise exception 'username_invalid'; end if;

  if v_user = 'uzb_dasturchii' then
    if exists (select 1 from profiles where role = 'dev') then raise exception 'dev_exists'; end if;
    if not exists (select 1 from private_setup
                   where code_hash = crypt(coalesce(new.raw_user_meta_data->>'setup_code',''), code_hash))
      then raise exception 'setup_code_invalid'; end if;
    v_role := 'dev';
    delete from private_setup;               -- kod bir martalik: ishlatildi, o'chdi
  else
    select * into inv from invites where phone = v_phone and used_at is null for update;
    if found then
      v_role := inv.role; v_branch := inv.branch_id;
      update invites set used_at = now() where id = inv.id;
    end if;
  end if;

  insert into profiles (id, username, phone, role, branch_id, country_code)
  values (new.id, v_user, v_phone, v_role, v_branch, v_cc);
  insert into audit_log(actor, action, details)
  values (new.id, 'signup', jsonb_build_object('role', v_role, 'username', v_user));
  return new;
end $$;

create trigger on_auth_user_created after insert on auth.users
  for each row execute function handle_new_user();

-- =====================================================================
-- RPC: bo'sh/band tekshiruvi (ro'yxatdan o'tishda)
-- =====================================================================
create function check_available(p_username text, p_phone text) returns jsonb
language sql security definer set search_path = public as $$
  select jsonb_build_object(
    'username_free', not exists (select 1 from profiles where lower(username) = lower(p_username)),
    'phone_free',    not exists (select 1 from profiles where phone = p_phone));
$$;
grant execute on function check_available(text, text) to anon, authenticated;

-- =====================================================================
-- RPC: admin taklif qilish (dasturchi -> katta/mayda, katta -> mayda)
-- =====================================================================
create function create_invite(p_phone text, p_role user_role, p_branch uuid default null) returns void
language plpgsql security definer set search_path = public as $$
declare r user_role := me_role();
begin
  if p_phone !~ '^\+[1-9][0-9]{8,14}$' then raise exception 'phone_invalid'; end if;
  if r = 'dev' then
    if p_role not in ('big','staff') or p_branch is null then raise exception 'forbidden'; end if;
  elsif r = 'big' then
    if p_role <> 'staff' then raise exception 'forbidden'; end if;
    p_branch := me_branch();
  else raise exception 'forbidden'; end if;

  if not exists (select 1 from branches where id = p_branch and status = 'active') then raise exception 'branch_inactive'; end if;
  if exists (select 1 from profiles where phone = p_phone) then raise exception 'phone_taken'; end if;

  delete from invites where phone = p_phone and used_at is null;
  insert into invites(phone, role, branch_id, created_by) values (p_phone, p_role, p_branch, auth.uid());
  perform log_action('invite', jsonb_build_object('phone', p_phone, 'role', p_role, 'branch', p_branch));
end $$;
revoke execute on function create_invite(text, user_role, uuid) from public, anon;
grant  execute on function create_invite(text, user_role, uuid) to authenticated;

-- adminni bloklash / ochish (katta -> o'z filial xodimi, dasturchi -> hamma)
create function set_member_active(p_user uuid, p_active boolean) returns void
language plpgsql security definer set search_path = public as $$
declare r user_role := me_role(); t profiles%rowtype;
begin
  select * into t from profiles where id = p_user;
  if not found or t.role = 'dev' or p_user = auth.uid() then raise exception 'forbidden'; end if;
  if r = 'dev' then null;
  elsif r = 'big' and t.role = 'staff' and t.branch_id = me_branch() then null;
  else raise exception 'forbidden'; end if;
  update profiles set active = p_active where id = p_user;
  perform log_action('set_active', jsonb_build_object('user', p_user, 'active', p_active));
end $$;
revoke execute on function set_member_active(uuid, boolean) from public, anon;
grant  execute on function set_member_active(uuid, boolean) to authenticated;

-- filialni tasdiqlash / bloklash (faqat dasturchi)
create function set_branch_status(p_branch uuid, p_status branch_status) returns void
language plpgsql security definer set search_path = public as $$
begin
  if me_role() <> 'dev' then raise exception 'forbidden'; end if;
  update branches set status = p_status where id = p_branch;
  perform log_action('branch_status', jsonb_build_object('branch', p_branch, 'status', p_status));
end $$;
revoke execute on function set_branch_status(uuid, branch_status) from public, anon;
grant  execute on function set_branch_status(uuid, branch_status) to authenticated;

-- =====================================================================
-- RPC: mamlakatni almashtirish (30 kunda faqat 1 marta)
-- =====================================================================
create function change_country(p_code text) returns void
language plpgsql security definer set search_path = public as $$
declare t profiles%rowtype;
begin
  select * into t from profiles where id = auth.uid() and active;
  if not found then raise exception 'forbidden'; end if;
  if not exists (select 1 from countries where code = upper(p_code)) then raise exception 'country_invalid'; end if;
  if t.country_code is not null and t.country_changed_at is not null
     and t.country_changed_at > now() - interval '30 days' then raise exception 'too_soon'; end if;
  update profiles set country_code = upper(p_code),
         country_changed_at = case when t.country_code is null then null else now() end
   where id = auth.uid();
end $$;
revoke execute on function change_country(text) from public, anon;
grant  execute on function change_country(text) to authenticated;

-- =====================================================================
-- Katalog: o'z mamlakati; bo'lmasa eng yaqin mamlakat
-- =====================================================================
create function catalog(p_country text) returns setof products
language sql stable security definer set search_path = public as $$
  with cand as (
    select upper(p_country) as c, 0 as ord
    union all
    select n, ord::int from countries k, unnest(k.neighbors) with ordinality as t(n, ord) where k.code = upper(p_country)
  ), chosen as (
    select c from cand
    where exists (select 1 from products p where p.country_code = cand.c and p.active and p.stock > 0)
    order by ord limit 1
  )
  select p.* from products p join chosen on p.country_code = chosen.c where p.active;
$$;
grant execute on function catalog(text) to anon, authenticated;

-- =====================================================================
-- Mahsulot trigeri: mamlakat har doim filialdan olinadi
-- =====================================================================
create function products_set_country() returns trigger language plpgsql as $$
begin
  select country_code into new.country_code from branches where id = new.branch_id;
  return new;
end $$;
create trigger products_country_trg before insert or update on products
  for each row execute function products_set_country();

-- =====================================================================
-- RLS (qatordagi ruxsat qoidalari)
-- =====================================================================
alter table countries     enable row level security;
alter table branches      enable row level security;
alter table profiles      enable row level security;
alter table invites       enable row level security;
alter table products      enable row level security;
alter table audit_log     enable row level security;
alter table private_setup enable row level security;   -- qoida yo'q = API orqali hech kim ko'ra olmaydi

create policy countries_read on countries for select using (true);

create policy branches_read on branches for select using (
  status = 'active' or me_role() = 'dev' or id = me_branch() or created_by = auth.uid());
create policy branches_insert on branches for insert to authenticated
  with check (status = 'pending' and created_by = auth.uid());

create policy profiles_read on profiles for select to authenticated using (
  id = auth.uid() or me_role() = 'dev' or (me_role() = 'big' and branch_id = me_branch()));

create policy invites_read on invites for select to authenticated using (
  me_role() = 'dev' or (me_role() = 'big' and branch_id = me_branch()));

create policy products_read on products for select using (
  active or me_role() = 'dev' or branch_id = me_branch());
create policy products_write on products for all to authenticated
  using      (me_role() = 'dev' or (me_role() in ('big','staff') and branch_id = me_branch()))
  with check (me_role() = 'dev' or (me_role() in ('big','staff') and branch_id = me_branch()));

create policy audit_read on audit_log for select to authenticated using (me_role() = 'dev');

-- =====================================================================
-- QO'LDA BAJARILADI: dasturchi uchun BIR MARTALIK maxfiy kod.
-- 'MENING-MAXFIY-KODIM-123' o'rniga O'ZINGIZNING uzun kodingizni yozing
-- va uni hech kimga bermang. Bu qatorni alohida RUN qiling:
--
-- insert into private_setup(code_hash) values (crypt('MENING-MAXFIY-KODIM-123', gen_salt('bf')));
-- =====================================================================
