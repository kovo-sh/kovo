# Framework Audit: Spring Boot & Spring Security
Tags: framework, springboot, java, spring-security, actuator, spel, jpa, authz
Summary: Audit Spring Boot SecurityFilterChain rules, Actuator endpoints, SpEL expressions, JPA/Hibernate queries, Jackson deserialization, and path-matching quirks using offline SAST and safe probes.

## 1. High-Risk Spring Boot Surfaces
Inspect `/repos` via `run_sast_scan` (`engines: ["opengrep", "ast-grep"]`) before live probing:
1. **`SecurityFilterChain` & Path-Matching Discrepancies:**
   - Audit `requestMatchers(...)` ordering (`permitAll()` before `authenticated()`, overly broad `/api/**` exemptions, or missing `.anyRequest().authenticated()`).
   - Check `@EnableMethodSecurity` and `@PreAuthorize` / `@Secured` annotations on `@RestController` methods; watch for missing tenant ownership checks (`#id` owned by `authentication.name`).
   - Watch for path normalization mismatches (trailing slash, semicolon matrix variables, encoded slashes) between custom servlet `Filter` / `HandlerInterceptor` auth checks and Spring MVC controller mapping.
2. **Spring Boot Actuator Exposure:**
   - Check `application.properties` / `application.yml` for `management.endpoints.web.exposure.include=*` or exposed `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`, `/actuator/beans`, `/actuator/configprops`, `/actuator/jolokia`.
3. **SpEL, Template & SQL/JPQL Sinks:**
   - Flag `SpelExpressionParser.parseExpression(userInput)` evaluated with `StandardEvaluationContext` (instead of `SimpleEvaluationContext`).
   - Flag JDBC `Statement.executeQuery("..." + input)`, Hibernate/JPA `entityManager.createQuery("..." + input)`, or MyBatis `${param}` (unsafe string substitution vs safe `#{param}`).
   - Check Thymeleaf view name returns (`return "user/" + view`) for fragment expression injection.
4. **Deserialization & Mass Assignment:**
   - Flag Jackson `enableDefaultTyping()` / `activateDefaultTyping(LaissezFaireSubTypeValidator.instance)` or `ObjectInputStream.readObject()` on untrusted input.
   - Check `@ModelAttribute` / `@RequestBody` binding directly to JPA `@Entity` classes without `@InitBinder` `setDisallowedFields` or dedicated DTOs.
5. **CORS & CSRF:**
   - Flag `allowedOriginPatterns("*")` with `allowCredentials(true)`, or `csrf().disable()` on cookie-session apps.

## 2. Offline Static & AST Triage
- Run `run_sast_scan` (`opengrep`, `ast-grep`) across `src/main/java/**` and `src/main/resources/application*.{yml,yaml,properties}`.
- Audit `pom.xml` / `build.gradle` with `query_cves` for Spring Framework / Spring Security / Jackson advisories (`cve_hypothesis` only until reachability is verified).

## 3. Safe Live Verification
- Run `run_safe_templates` (`techTags: ["springboot"]`) and `probe_surface` (`mode: "paths"`, `wordlist: "debug-actuator"`).
- Use `probe_differential` (`authz_matrix`, `sqli_boolean`, `ssti_math` with benign `#{a*b}` prime math) strictly through `RequestBroker`.

## 4. Closure & Replay Spec Discipline
- Confirm dynamic findings via `http_chain`, `sql_boolean_diff`, or Tier-3 non-destructive `rce_proof` (`dynamic_math` only with HITL approval).
- Never attempt destructive Actuator mutations (such as lifecycle-termination or runtime environment-mutation endpoints).
- Record `ruled_out` only with exact `SecurityFilterChain` / `@PreAuthorize` `file:line` or negative-control `exchangeId`.
