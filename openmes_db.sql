--
-- PostgreSQL database dump
--

\restrict ZzKzPxE18FflzGNL8fDtF8Uu9rih9VU7PCZ51had9JmWAoVEUxeZuWD8zZtmgjg

-- Dumped from database version 18.1
-- Dumped by pg_dump version 18.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: calculate_module_permission(boolean, boolean, boolean, boolean, boolean); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.calculate_module_permission(p_read boolean, p_create boolean, p_update boolean, p_delete boolean, p_advanced boolean) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    result INTEGER := 0;
BEGIN
    -- 五位二进制权限：读(1)、建(2)、改(4)、删(8)、高(16)
    IF p_read THEN result := result + 1; END IF;
    IF p_create THEN result := result + 2; END IF;
    IF p_update THEN result := result + 4; END IF;
    IF p_delete THEN result := result + 8; END IF;
    IF p_advanced THEN result := result + 16; END IF;
    
    RETURN result;
END;
$$;


ALTER FUNCTION public.calculate_module_permission(p_read boolean, p_create boolean, p_update boolean, p_delete boolean, p_advanced boolean) OWNER TO postgres;

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_updated_at_column() OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: operator_groups; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.operator_groups (
    id integer NOT NULL,
    group_name character varying(100) NOT NULL,
    operator_name character varying(100) NOT NULL,
    create_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    update_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    password_hash character varying(256),
    last_login timestamp without time zone,
    group_owner boolean DEFAULT false,
    signature_file character varying(200),
    signature_time timestamp without time zone
);


ALTER TABLE public.operator_groups OWNER TO postgres;

--
-- Name: operator_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.operator_groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.operator_groups_id_seq OWNER TO postgres;

--
-- Name: operator_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.operator_groups_id_seq OWNED BY public.operator_groups.id;


--
-- Name: process_options; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.process_options (
    id integer NOT NULL,
    process_name character varying(100) NOT NULL,
    create_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    update_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    linked_groups text DEFAULT '[]'::text,
    linked_next_processes text DEFAULT '[]'::text
);


ALTER TABLE public.process_options OWNER TO postgres;

--
-- Name: process_options_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.process_options_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.process_options_id_seq OWNER TO postgres;

--
-- Name: process_options_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.process_options_id_seq OWNED BY public.process_options.id;


--
-- Name: production_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.production_logs (
    id integer NOT NULL,
    log_type character varying(50) NOT NULL,
    action character varying(100) NOT NULL,
    user_type character varying(20) NOT NULL,
    user_id integer,
    username character varying(100) NOT NULL,
    target_id integer,
    target_info text,
    ip_address character varying(45),
    user_agent text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.production_logs OWNER TO postgres;

--
-- Name: production_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.production_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.production_logs_id_seq OWNER TO postgres;

--
-- Name: production_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.production_logs_id_seq OWNED BY public.production_logs.id;


--
-- Name: production_records; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.production_records (
    id integer NOT NULL,
    product_code character varying(50) NOT NULL,
    process character varying(100) NOT NULL,
    number integer NOT NULL,
    create_time timestamp without time zone,
    update_time timestamp without time zone,
    operators character varying(200) DEFAULT ''::character varying NOT NULL,
    creator character varying(50) NOT NULL,
    next_process character varying(100),
    note text,
    is_freeze boolean DEFAULT false
);


ALTER TABLE public.production_records OWNER TO postgres;

--
-- Name: production_records_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.production_records_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.production_records_id_seq OWNER TO postgres;

--
-- Name: production_records_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.production_records_id_seq OWNED BY public.production_records.id;


--
-- Name: production_users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.production_users (
    id integer NOT NULL,
    username character varying(50) NOT NULL,
    password_hash character varying(256) NOT NULL,
    create_time timestamp without time zone,
    update_time timestamp without time zone,
    granted_by integer,
    user_level integer DEFAULT 0,
    permissions jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.production_users OWNER TO postgres;

--
-- Name: production_users_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.production_users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.production_users_id_seq OWNER TO postgres;

--
-- Name: production_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.production_users_id_seq OWNED BY public.production_users.id;


--
-- Name: operator_groups id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.operator_groups ALTER COLUMN id SET DEFAULT nextval('public.operator_groups_id_seq'::regclass);


--
-- Name: process_options id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.process_options ALTER COLUMN id SET DEFAULT nextval('public.process_options_id_seq'::regclass);


--
-- Name: production_logs id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.production_logs ALTER COLUMN id SET DEFAULT nextval('public.production_logs_id_seq'::regclass);


--
-- Name: production_records id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.production_records ALTER COLUMN id SET DEFAULT nextval('public.production_records_id_seq'::regclass);


--
-- Name: production_users id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.production_users ALTER COLUMN id SET DEFAULT nextval('public.production_users_id_seq'::regclass);


--
-- Data for Name: operator_groups; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.operator_groups (id, group_name, operator_name, create_time, update_time, password_hash, last_login, group_owner, signature_file, signature_time) FROM stdin;
\.


--
-- Data for Name: process_options; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.process_options (id, process_name, create_time, update_time, linked_groups, linked_next_processes) FROM stdin;
\.


--
-- Data for Name: production_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.production_logs (id, log_type, action, user_type, user_id, username, target_id, target_info, ip_address, user_agent, created_at) FROM stdin;
\.


--
-- Data for Name: production_records; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.production_records (id, product_code, process, number, create_time, update_time, operators, creator, next_process, note, is_freeze) FROM stdin;
\.


--
-- Data for Name: production_users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.production_users (id, username, password_hash, create_time, update_time, granted_by, user_level, permissions) FROM stdin;
\.


--
-- Name: operator_groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.operator_groups_id_seq', 206, true);


--
-- Name: process_options_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.process_options_id_seq', 45, true);


--
-- Name: production_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.production_logs_id_seq', 25, true);


--
-- Name: production_records_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.production_records_id_seq', 1763, true);


--
-- Name: production_users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.production_users_id_seq', 39, true);


--
-- Name: operator_groups operator_groups_group_name_operator_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.operator_groups
    ADD CONSTRAINT operator_groups_group_name_operator_name_key UNIQUE (group_name, operator_name);


--
-- Name: operator_groups operator_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.operator_groups
    ADD CONSTRAINT operator_groups_pkey PRIMARY KEY (id);


--
-- Name: process_options process_options_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.process_options
    ADD CONSTRAINT process_options_pkey PRIMARY KEY (id);


--
-- Name: process_options process_options_process_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.process_options
    ADD CONSTRAINT process_options_process_name_key UNIQUE (process_name);


--
-- Name: production_logs production_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.production_logs
    ADD CONSTRAINT production_logs_pkey PRIMARY KEY (id);


--
-- Name: production_records production_records_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.production_records
    ADD CONSTRAINT production_records_pkey PRIMARY KEY (id);


--
-- Name: production_users production_users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.production_users
    ADD CONSTRAINT production_users_pkey PRIMARY KEY (id);


--
-- Name: production_users production_users_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.production_users
    ADD CONSTRAINT production_users_username_key UNIQUE (username);


--
-- Name: idx_operator_groups_group_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_operator_groups_group_name ON public.operator_groups USING btree (group_name);


--
-- Name: idx_operator_groups_group_owner; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_operator_groups_group_owner ON public.operator_groups USING btree (group_owner);


--
-- Name: idx_operator_groups_signature_file; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_operator_groups_signature_file ON public.operator_groups USING btree (signature_file);


--
-- Name: idx_production_logs_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_production_logs_created_at ON public.production_logs USING btree (created_at);


--
-- Name: idx_production_logs_log_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_production_logs_log_type ON public.production_logs USING btree (log_type);


--
-- Name: idx_production_logs_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_production_logs_user_id ON public.production_logs USING btree (user_id);


--
-- Name: idx_users_level; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_level ON public.production_users USING btree (user_level);


--
-- Name: idx_users_permissions; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_permissions ON public.production_users USING gin (permissions);


--
-- Name: idx_users_username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_username ON public.production_users USING btree (username);


--
-- Name: production_users production_users_granted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.production_users
    ADD CONSTRAINT production_users_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.production_users(id);


--
-- PostgreSQL database dump complete
--

\unrestrict ZzKzPxE18FflzGNL8fDtF8Uu9rih9VU7PCZ51had9JmWAoVEUxeZuWD8zZtmgjg

