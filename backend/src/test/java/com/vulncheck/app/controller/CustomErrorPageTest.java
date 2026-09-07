package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.repository.UserRepository;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * closed-mode backlog item 411: URL直打ち等で403/404/500に到達したとき、非エンジニア向けの日本語
 * カスタムエラーページ（{@code templates/error/403.html}・{@code 404.html}・{@code 500.html}）が
 * Spring Bootの素のwhitelabelエラーページの代わりに実際に表示されること、かつ500応答が内部の
 * スタックトレース・例外クラス名・例外メッセージを一切露出しないことを検証する。
 *
 * <p>{@code @WebMvcTest}/{@code @AutoConfigureMockMvc}のMockMvcは実サーブレットコンテナの
 * エラーページ転送（{@code sendError}/未処理例外 → {@code /error}への forward）を再現しない
 * （2026-09-07実測 — MockMvcではボディが空、または例外がそのまま{@code perform()}から再送出される
 * だけで、{@code BasicErrorController}によるテンプレート解決を経由しない）。そのため既存の
 * {@code SessionCookieSecureDefaultTest}と同じ{@code @SpringBootTest(webEnvironment = RANDOM_PORT)}
 * + {@link TestRestTemplate}の実サーバー経路を使い、実際にTomcatが返すレスポンスを検証する。
 *
 * <p><b>注意（PR#310 senior-review REVISE指摘）:</b> このテストは{@code @SpringBootTest}であり、
 * {@code backend/src/test/resources/application.yml}がテストクラスパス上で本番
 * {@code backend/src/main/resources/application.yml}を完全に上書き（shadow）する
 * （{@link com.vulncheck.app.config.SessionCookieConfigBindingTest}のjavadoc参照）。そのため
 * {@link #serverErrorRendersCustomJapanesePageWithoutLeakingStackTrace}が検証しているのは、
 * テスト用YAMLに{@code server.error.*}キーが一切無いことによりSpring Boot組み込みのデフォルト値
 * （現バージョンではたまたま{@code never}/{@code false}）が効いている、という状態であって、
 * 本番YAMLが実際に{@code server.error.include-stacktrace: never}等を明示指定している効果そのもの
 * ではない。本番YAMLのその設定値を直接バインドして検証するのは
 * {@link com.vulncheck.app.config.ErrorPropertiesConfigBindingTest}であり、スタックトレース等の
 * 非露出をカバーする一次テストはそちらを参照すること。このテストは「テンプレートが正しく描画され、
 * それ単体としてスタックトレース等の文字列を含まない」ことのend-to-end確認としては引き続き有効。
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class CustomErrorPageTest {

    private static final Pattern CSRF_TOKEN_PATTERN = Pattern.compile("_csrf\"[^>]*?value=\"([^\"]+)\"");

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /** MockMvcではなくTestRestTemplate経由で確実に500を起こすためだけのテスト専用エンドポイント。
     *  本番コードには存在しない。 */
    @TestConfiguration
    static class ThrowingEndpointConfig {

        @RestController
        static class ThrowingController {

            @GetMapping("/error-page-test/boom")
            public String boom() {
                throw new IllegalStateException("boom - CustomErrorPageTest専用の疑似障害");
            }
        }
    }

    @Test
    void notFoundRendersCustomJapanesePageInsteadOfWhitelabel() {
        String sessionCookie = loginAndGetSessionCookie();

        ResponseEntity<String> response = getAuthenticated("/this-path-does-not-exist-xyz", sessionCookie);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).contains("ページが見つかりません");
        assertThat(response.getBody()).contains("ホームに戻る");
        assertThat(response.getBody()).doesNotContain("Whitelabel Error Page");
    }

    @Test
    void forbiddenRendersCustomJapanesePageInsteadOfWhitelabel() {
        // /admin/** はROLE_ADMIN専用（SecurityConfig）。一般ユーザーがアクセスするとAccessDeniedException。
        String sessionCookie = loginAndGetSessionCookie();

        ResponseEntity<String> response = getAuthenticated("/admin/cpe-dictionary", sessionCookie);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody()).contains("アクセス権限がありません");
        assertThat(response.getBody()).contains("ホームに戻る");
        assertThat(response.getBody()).doesNotContain("Whitelabel Error Page");
    }

    @Test
    void serverErrorRendersCustomJapanesePageWithoutLeakingStackTrace() {
        String sessionCookie = loginAndGetSessionCookie();

        ResponseEntity<String> response = getAuthenticated("/error-page-test/boom", sessionCookie);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).contains("サーバーエラーが発生しました");
        assertThat(response.getBody()).contains("ホームに戻る");
        assertThat(response.getBody()).doesNotContain("Whitelabel Error Page");
        // セキュリティ観点(item411 やること4): スタックトレース・例外クラス名・例外メッセージが
        // 一切露出しないこと。ただしこのアサーションが押さえているのはテスト用YAML下でのSpring Boot
        // 組み込みデフォルトの挙動であり、本番application.ymlのserver.error.*設定そのものの検証は
        // ErrorPropertiesConfigBindingTestが担う(クラスjavadoc参照)。
        assertThat(response.getBody()).doesNotContain("IllegalStateException");
        assertThat(response.getBody()).doesNotContain("boom - CustomErrorPageTest");
        assertThat(response.getBody()).doesNotContain("at com.vulncheck");
        assertThat(response.getBody()).doesNotContain("java.lang.");
    }

    /** テスト専用ユーザーを作成し、実際のフォームログイン（CSRFトークン込み）を行って、認証済み
     *  セッションのCookieヘッダ値を返す。 */
    private String loginAndGetSessionCookie() {
        String email = "error-page-test-" + UUID.randomUUID() + "@example.com";
        String rawPassword = "password123";
        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        userRepository.save(user);

        restTemplate.getRestTemplate().setRequestFactory(noRedirectRequestFactory());

        ResponseEntity<String> loginPage = restTemplate.getForEntity("/login", String.class);
        String initialCookie = firstSessionCookie(loginPage.getHeaders());
        String csrfToken = extractCsrfToken(loginPage.getBody());

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("username", email);
        form.add("password", rawPassword);
        form.add("_csrf", csrfToken);

        HttpHeaders postHeaders = new HttpHeaders();
        postHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        if (initialCookie != null) {
            postHeaders.add(HttpHeaders.COOKIE, initialCookie);
        }

        ResponseEntity<String> loginResponse =
                restTemplate.postForEntity("/login", new HttpEntity<>(form, postHeaders), String.class);
        assertThat(loginResponse.getStatusCode()).as("POST /login should redirect on success").isEqualTo(HttpStatus.FOUND);

        String authenticatedCookie = firstSessionCookie(loginResponse.getHeaders());
        return authenticatedCookie != null ? authenticatedCookie : initialCookie;
    }

    private static String extractCsrfToken(String html) {
        Matcher matcher = CSRF_TOKEN_PATTERN.matcher(html == null ? "" : html);
        assertThat(matcher.find()).as("CSRF token hidden field on /login page").isTrue();
        return matcher.group(1);
    }

    private static String firstSessionCookie(HttpHeaders headers) {
        List<String> setCookies = headers.get(HttpHeaders.SET_COOKIE);
        if (setCookies == null) {
            return null;
        }
        return setCookies.stream()
                .filter(cookie -> cookie.startsWith("JSESSIONID"))
                .findFirst()
                .map(cookie -> cookie.split(";", 2)[0])
                .orElse(null);
    }

    /** Same shape as {@code RestClientConfig#noRedirectRequestFactory} (package-private there, so
     *  duplicated here) — disables automatic redirect-following so a 302 response's own headers
     *  (in particular {@code Set-Cookie}) can be inspected directly rather than whatever the
     *  followed redirect target itself returns. */
    private static SimpleClientHttpRequestFactory noRedirectRequestFactory() {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.defaults()
                .withConnectTimeout(Duration.ofSeconds(5))
                .withReadTimeout(Duration.ofSeconds(5))
                .withRedirects(ClientHttpRequestFactorySettings.Redirects.DONT_FOLLOW);
        return (SimpleClientHttpRequestFactory) ClientHttpRequestFactoryBuilder.simple().build(settings);
    }

    private ResponseEntity<String> getAuthenticated(String path, String sessionCookie) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.COOKIE, sessionCookie);
        // BasicErrorController content-negotiates on Accept — without this, TestRestTemplate's
        // default Accept (driven by its registered message converters) makes it pick the JSON
        // error body instead of resolving our error/*.html templates. This mirrors how an actual
        // browser navigation (which always sends Accept: text/html) reaches this app.
        headers.setAccept(List.of(MediaType.TEXT_HTML));
        return restTemplate.exchange(path, HttpMethod.GET, new HttpEntity<>(headers), String.class);
    }
}
