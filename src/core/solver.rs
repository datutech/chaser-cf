//! Solver implementations for chaser-cf

use super::BrowserManager;
use crate::error::{ChaserError, ChaserResult};
use crate::models::{Cookie, ProxyConfig, WafSession, WafSessionOptions};

use chaser_oxide::auth::Credentials;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::Instant;

const FAKE_PAGE_HTML: &str = include_str!("../resources/fake_page.html");

/// Get page source from a Cloudflare-protected URL.
pub async fn get_source(
    manager: &BrowserManager,
    url: &str,
    proxy: Option<ProxyConfig>,
) -> ChaserResult<String> {
    let _permit = manager.acquire_permit().await?;
    let ctx_id = manager.create_context(proxy.as_ref(), false).await?;
    let (page, chaser) = manager.new_page(ctx_id, "about:blank").await?;

    setup_proxy_auth(&page, proxy.as_ref()).await?;

    chaser
        .goto(url)
        .await
        .map_err(|e| ChaserError::NavigationFailed(e.to_string()))?;

    wait_for_clearance(&page, &chaser, 30).await;

    page.content()
        .await
        .map_err(|e| ChaserError::Internal(e.to_string()))
}

/// Navigate to a Cloudflare-protected URL with a stealth browser, solve any interactive
/// challenge (including Turnstile managed challenges via CDP shadow-root click), and
/// return the resulting cookies + User-Agent for use in subsequent HTTP requests.
pub async fn solve_waf_session(
    manager: &BrowserManager,
    url: &str,
    proxy: Option<ProxyConfig>,
    options: WafSessionOptions,
    operation_timeout: Duration,
) -> ChaserResult<WafSession> {
    let deadline = Instant::now() + operation_timeout;
    let timeout_error = || ChaserError::Timeout(operation_timeout.as_millis() as u64);

    let _permit = tokio::time::timeout_at(deadline, manager.acquire_permit())
        .await
        .map_err(|_| timeout_error())??;
    let ctx_id = tokio::time::timeout_at(
        deadline,
        manager.create_context(proxy.as_ref(), options.fresh_context),
    )
    .await
    .map_err(|_| timeout_error())??;

    let result = match tokio::time::timeout_at(deadline, async {
        let (page, chaser) = manager.new_page(ctx_id.clone(), "about:blank").await?;

        setup_proxy_auth(&page, proxy.as_ref()).await?;

        chaser
            .goto(url)
            .await
            .map_err(|e| ChaserError::NavigationFailed(e.to_string()))?;

        wait_for_clearance(&page, &chaser, 90).await;

        let raw_cookies = page
            .get_cookies()
            .await
            .map_err(|e| ChaserError::CookieExtractionFailed(e.to_string()))?;

        let cookies: Vec<Cookie> = raw_cookies
            .into_iter()
            .map(|c| Cookie {
                name: c.name,
                value: c.value,
                domain: Some(c.domain),
                path: Some(c.path),
                expires: Some(c.expires),
                http_only: Some(c.http_only),
                secure: Some(c.secure),
                same_site: c.same_site.map(|s| format!("{s:?}")),
            })
            .collect();

        let user_agent = chaser
            .evaluate("navigator.userAgent")
            .await
            .ok()
            .and_then(|v| v?.as_str().map(str::to_owned))
            .unwrap_or_default();

        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), user_agent);

        Ok(WafSession::new(cookies, headers))
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(timeout_error()),
    };

    // Proxy contexts are isolated too, so dispose every context created for
    // this operation. Preserve the solve result if cleanup alone fails.
    if let Some(ctx_id) = ctx_id {
        match tokio::time::timeout(Duration::from_secs(5), manager.dispose_context(ctx_id)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "failed to dispose WAF session browser context");
            }
            Err(_) => {
                tracing::warn!("timed out disposing WAF session browser context");
            }
        }
    }

    result
}

/// Solve Turnstile with full page load.
pub async fn solve_turnstile_max(
    manager: &BrowserManager,
    url: &str,
    proxy: Option<ProxyConfig>,
) -> ChaserResult<String> {
    let _permit = manager.acquire_permit().await?;
    let ctx_id = manager.create_context(proxy.as_ref(), false).await?;
    let (page, chaser) = manager.new_page(ctx_id, "about:blank").await?;

    setup_proxy_auth(&page, proxy.as_ref()).await?;

    page.evaluate_on_new_document(TURNSTILE_EXTRACTOR_SCRIPT)
        .await
        .map_err(|e| ChaserError::Internal(e.to_string()))?;

    chaser
        .goto(url)
        .await
        .map_err(|e| ChaserError::NavigationFailed(e.to_string()))?;

    wait_for_turnstile_token(&page, 60).await
}

/// Solve Turnstile with minimal resource usage (request interception mode).
pub async fn solve_turnstile_min(
    manager: &BrowserManager,
    url: &str,
    site_key: &str,
    proxy: Option<ProxyConfig>,
) -> ChaserResult<String> {
    use chaser_oxide::cdp::browser_protocol::fetch::EventRequestPaused;
    use chaser_oxide::cdp::browser_protocol::network::ResourceType;
    use futures::StreamExt;

    let _permit = manager.acquire_permit().await?;
    let ctx_id = manager.create_context(proxy.as_ref(), false).await?;
    let (page, chaser) = manager.new_page(ctx_id, "about:blank").await?;

    setup_proxy_auth(&page, proxy.as_ref()).await?;

    let fake_html = FAKE_PAGE_HTML.replace("<site-key>", site_key);

    chaser
        .enable_request_interception("*", Some(ResourceType::Document))
        .await
        .map_err(|e| ChaserError::Internal(format!("enable interception: {e}")))?;

    let mut request_events = page
        .event_listener::<EventRequestPaused>()
        .await
        .map_err(|e| ChaserError::Internal(format!("request listener: {e}")))?;

    let url_str = url.to_string();
    let fake_html_clone = fake_html.clone();
    let chaser_clone = chaser.clone();

    let intercept_handle = tokio::spawn(async move {
        while let Some(event) = request_events.next().await {
            let req_url = &event.request.url;
            let is_target = req_url == &url_str
                || req_url == &format!("{}/", url_str)
                || req_url.starts_with(&url_str);

            if is_target && event.resource_type == ResourceType::Document {
                let _ = chaser_clone
                    .fulfill_request_html(event.request_id.clone(), &fake_html_clone, 200)
                    .await;
            } else {
                let _ = chaser_clone
                    .continue_request(event.request_id.clone())
                    .await;
            }
        }
    });

    chaser
        .goto(url)
        .await
        .map_err(|e| ChaserError::NavigationFailed(e.to_string()))?;

    let token = wait_for_turnstile_token(&page, 60).await?;

    intercept_handle.abort();
    let _ = chaser.disable_request_interception().await;

    Ok(token)
}

// ─── helpers ────────────────────────────────────────────────────────────────

async fn setup_proxy_auth(
    page: &chaser_oxide::Page,
    proxy: Option<&ProxyConfig>,
) -> ChaserResult<()> {
    if let Some(p) = proxy {
        if let (Some(username), Some(password)) = (&p.username, &p.password) {
            page.authenticate(Credentials {
                username: username.clone(),
                password: password.clone(),
            })
            .await
            .map_err(|e| ChaserError::Internal(format!("proxy auth: {e}")))?;
        }
    }
    Ok(())
}

/// Poll until `cf_clearance` appears (meaning the challenge was solved) or the
/// timeout expires.
///
/// For the first `PASSIVE_WAIT_MS` milliseconds we do nothing — the CF managed
/// challenge JS runs its invisible PoW/fingerprint in this window. Polling the
/// DOM while it runs causes timing anomalies that raise the bot score. After
/// the passive window we check whether a Turnstile widget has appeared and, if
/// so, click it using the shadow-root CDP traversal.
async fn wait_for_clearance(
    page: &chaser_oxide::Page,
    chaser: &chaser_oxide::ChaserPage,
    timeout_seconds: u64,
) {
    const PASSIVE_WAIT_MS: u64 = 6_000;
    const CLICK_INTERVAL_MS: u64 = 1_200;

    let started = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_seconds);
    let mut last_click = started - Duration::from_secs(30);

    loop {
        if has_clearance_cookie(page).await {
            tokio::time::sleep(Duration::from_millis(500)).await;
            return;
        }

        if started.elapsed() >= timeout {
            return;
        }

        // Only start DOM inspection / clicking after the passive window.
        if started.elapsed().as_millis() as u64 >= PASSIVE_WAIT_MS
            && last_click.elapsed().as_millis() as u64 >= CLICK_INTERVAL_MS
            && try_click_challenge(chaser).await
        {
            last_click = std::time::Instant::now();
        }

        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

/// Return true if the browser has a `cf_clearance` cookie for any domain.
async fn has_clearance_cookie(page: &chaser_oxide::Page) -> bool {
    page.get_cookies()
        .await
        .map(|cookies| cookies.iter().any(|c| c.name == "cf_clearance"))
        .unwrap_or(false)
}

/// Click the Turnstile challenge element by traversing its closed shadow root via CDP.
///
/// Cloudflare's Turnstile widget lives inside a CLOSED shadow root. JS's
/// `element.shadowRoot` returns null for these, but CDP's `DOM.getDocument` with
/// `pierce: true` exposes them as `node.shadow_roots` — identical to what the Python
/// CF-Clearance-Scraper does with `parent.shadow_roots[0]`.
async fn try_click_challenge(chaser: &chaser_oxide::ChaserPage) -> bool {
    use chaser_oxide::cdp::browser_protocol::dom::{GetBoxModelParams, GetDocumentParams};

    let page = chaser.raw_page();

    let doc = match page
        .execute(GetDocumentParams {
            depth: Some(-1),
            pierce: Some(true),
        })
        .await
    {
        Ok(r) => r,
        Err(error) => {
            tracing::debug!(%error, "Turnstile DOM.getDocument failed");
            return false;
        }
    };

    let Some(target) = find_challenge_target(&doc.result.root) else {
        tracing::debug!("Turnstile response input/iframe not found in pierced DOM");
        return false;
    };

    // Prefer the actual checkbox when Chrome exposes the iframe's content
    // document. If it is unavailable (for example for an OOPIF), use a point
    // in the checkbox region near the left edge of the Turnstile iframe.
    let (target_id, click_mode) = match target.checkbox_node_id {
        Some(checkbox_id) => (checkbox_id, ChallengeClickMode::ElementCenter),
        None => (
            target.iframe_node_id,
            ChallengeClickMode::IframeCheckboxRegion,
        ),
    };

    let load_quad = |node_id| async move {
        page.execute(GetBoxModelParams {
            node_id: Some(node_id),
            backend_node_id: None,
            object_id: None,
        })
        .await
        .map(|result| result.result.model.content.inner().clone())
    };

    let (content, click_mode) = match load_quad(target_id).await {
        Ok(content) => (content, click_mode),
        Err(error) if target.checkbox_node_id.is_some() => {
            tracing::debug!(%error, "Turnstile checkbox box model unavailable; using iframe fallback");
            match load_quad(target.iframe_node_id).await {
                Ok(content) => (content, ChallengeClickMode::IframeCheckboxRegion),
                Err(error) => {
                    tracing::debug!(%error, "Turnstile iframe box model unavailable");
                    return false;
                }
            }
        }
        Err(error) => {
            tracing::debug!(%error, "Turnstile iframe box model unavailable");
            return false;
        }
    };

    if content.len() < 8 {
        tracing::debug!(
            points = content.len(),
            "Turnstile box model has an invalid content quad"
        );
        return false;
    }

    let left_x = (content[0] + content[6]) / 2.0;
    let left_y = (content[1] + content[7]) / 2.0;
    let right_x = (content[2] + content[4]) / 2.0;
    let right_y = (content[3] + content[5]) / 2.0;
    let width = ((right_x - left_x).powi(2) + (right_y - left_y).powi(2)).sqrt();
    let height = ((content[6] - content[0]).powi(2) + (content[7] - content[1]).powi(2)).sqrt();

    if width < 2.0 || height < 2.0 {
        tracing::debug!(width, height, "Turnstile target has no clickable area");
        return false;
    }

    let (cx, cy) = match click_mode {
        ChallengeClickMode::ElementCenter => (
            (content[0] + content[2] + content[4] + content[6]) / 4.0,
            (content[1] + content[3] + content[5] + content[7]) / 4.0,
        ),
        ChallengeClickMode::IframeCheckboxRegion => {
            const CHECKBOX_HORIZONTAL_POSITION: f64 = 0.10;
            (
                left_x + (right_x - left_x) * CHECKBOX_HORIZONTAL_POSITION,
                left_y + (right_y - left_y) * CHECKBOX_HORIZONTAL_POSITION,
            )
        }
    };

    // Compute all random values in a synchronous block so ThreadRng is dropped
    // before any await point — ThreadRng is !Send and would poison the future.
    let (tx, ty, curve_points, post_pause_ms) = {
        use rand::Rng as _;
        let mut rng = rand::rng();

        let tx = cx + rng.random_range(-5.0..=5.0_f64);
        let ty = cy + rng.random_range(-4.0..=4.0_f64);

        // Ghost-cursor style: cubic Bezier from a random off-screen origin.
        // P0 = start (random position away from target), P3 = target.
        // P1, P2 are random control points that produce a natural arc.
        let p0x = tx + rng.random_range(-200.0..=-60.0_f64);
        let p0y = ty + rng.random_range(-120.0..=120.0_f64);
        let p1x = p0x + (tx - p0x) * rng.random_range(0.2..0.5_f64) + rng.random_range(-30.0..30.0);
        let p1y = p0y + (ty - p0y) * rng.random_range(0.1..0.4_f64) + rng.random_range(-40.0..40.0);
        let p2x = p0x + (tx - p0x) * rng.random_range(0.5..0.8_f64) + rng.random_range(-20.0..20.0);
        let p2y = p0y + (ty - p0y) * rng.random_range(0.5..0.9_f64) + rng.random_range(-20.0..20.0);

        let steps: u8 = rng.random_range(12..22);
        let mut points: Vec<(f64, f64, u64)> = Vec::with_capacity(steps as usize);
        for i in 1..=steps {
            let t = i as f64 / steps as f64;
            let u = 1.0 - t;
            // Cubic Bezier: B(t) = u³P0 + 3u²tP1 + 3ut²P2 + t³P3
            let bx =
                u * u * u * p0x + 3.0 * u * u * t * p1x + 3.0 * u * t * t * p2x + t * t * t * tx;
            let by =
                u * u * u * p0y + 3.0 * u * u * t * p1y + 3.0 * u * t * t * p2y + t * t * t * ty;
            // Slow down near the target (ease-in-out feel).
            let speed = (4.0 * t * (1.0 - t)).max(0.1);
            let step_ms = (rng.random_range(8.0..22.0_f64) / speed) as u64;
            points.push((bx, by, step_ms.min(80)));
        }

        let post_pause_ms = rng.random_range(40..120_u64);
        (tx, ty, points, post_pause_ms)
        // rng dropped here — no !Send value crosses any await below
    };

    for (bx, by, step_ms) in curve_points {
        if let Err(error) = page
            .move_mouse(chaser_oxide::layout::Point::new(bx, by))
            .await
        {
            tracing::debug!(%error, "Turnstile mouse movement failed");
            return false;
        }
        tokio::time::sleep(Duration::from_millis(step_ms)).await;
    }

    tokio::time::sleep(Duration::from_millis(post_pause_ms)).await;
    if let Err(error) = page.click(chaser_oxide::layout::Point::new(tx, ty)).await {
        tracing::debug!(%error, "Turnstile click failed");
        return false;
    }

    tracing::debug!(x = tx, y = ty, ?click_mode, "clicked Turnstile challenge");
    true
}

#[derive(Debug, Clone, Copy)]
enum ChallengeClickMode {
    ElementCenter,
    IframeCheckboxRegion,
}

#[derive(Debug, Clone, Copy)]
struct ChallengeTarget {
    iframe_node_id: chaser_oxide::cdp::browser_protocol::dom::NodeId,
    checkbox_node_id: Option<chaser_oxide::cdp::browser_protocol::dom::NodeId>,
}

/// Locate the Turnstile iframe associated with a response input. Cloudflare's
/// current layout places the hidden input next to (not inside) the closed
/// shadow host. When CDP exposes the iframe document, prefer its real checkbox.
fn find_challenge_target(
    node: &chaser_oxide::cdp::browser_protocol::dom::Node,
) -> Option<ChallengeTarget> {
    let children = node.children.as_deref().unwrap_or(&[]);

    if children.iter().any(is_turnstile_response_input) {
        for sibling in children {
            if !is_turnstile_response_input(sibling) {
                if let Some(iframe) = find_turnstile_iframe(sibling) {
                    return Some(target_from_iframe(iframe));
                }
            }
        }
    }

    // Retain a global iframe fallback for layouts where the response input is
    // inserted later than the widget or is not a sibling of the shadow host.
    if is_turnstile_iframe(node) {
        return Some(target_from_iframe(node));
    }

    for child in children {
        if let Some(target) = find_challenge_target(child) {
            return Some(target);
        }
    }
    for sr in node.shadow_roots.as_deref().unwrap_or(&[]) {
        if let Some(target) = find_challenge_target(sr) {
            return Some(target);
        }
    }
    if let Some(document) = node.content_document.as_deref() {
        if let Some(target) = find_challenge_target(document) {
            return Some(target);
        }
    }
    if let Some(template) = node.template_content.as_deref() {
        if let Some(target) = find_challenge_target(template) {
            return Some(target);
        }
    }
    None
}

fn target_from_iframe(iframe: &chaser_oxide::cdp::browser_protocol::dom::Node) -> ChallengeTarget {
    // Depending on the Chrome/CDP version, the frame document may be exposed
    // through `content_document` or as a child of the iframe owner node.
    let checkbox_node_id = find_checkbox_node(iframe);

    ChallengeTarget {
        iframe_node_id: iframe.node_id,
        checkbox_node_id,
    }
}

fn find_turnstile_iframe(
    node: &chaser_oxide::cdp::browser_protocol::dom::Node,
) -> Option<&chaser_oxide::cdp::browser_protocol::dom::Node> {
    if is_turnstile_iframe(node) {
        return Some(node);
    }

    for child in node.children.as_deref().unwrap_or(&[]) {
        if let Some(iframe) = find_turnstile_iframe(child) {
            return Some(iframe);
        }
    }
    for root in node.shadow_roots.as_deref().unwrap_or(&[]) {
        if let Some(iframe) = find_turnstile_iframe(root) {
            return Some(iframe);
        }
    }
    if let Some(document) = node.content_document.as_deref() {
        if let Some(iframe) = find_turnstile_iframe(document) {
            return Some(iframe);
        }
    }
    if let Some(template) = node.template_content.as_deref() {
        if let Some(iframe) = find_turnstile_iframe(template) {
            return Some(iframe);
        }
    }
    None
}

fn find_checkbox_node(
    node: &chaser_oxide::cdp::browser_protocol::dom::Node,
) -> Option<chaser_oxide::cdp::browser_protocol::dom::NodeId> {
    if attribute(node, "role").is_some_and(|value| value.eq_ignore_ascii_case("checkbox"))
        || (node.node_name.eq_ignore_ascii_case("input")
            && attribute(node, "type").is_some_and(|value| value.eq_ignore_ascii_case("checkbox")))
    {
        return Some(node.node_id);
    }

    for child in node.children.as_deref().unwrap_or(&[]) {
        if let Some(node_id) = find_checkbox_node(child) {
            return Some(node_id);
        }
    }
    for root in node.shadow_roots.as_deref().unwrap_or(&[]) {
        if let Some(node_id) = find_checkbox_node(root) {
            return Some(node_id);
        }
    }
    if let Some(document) = node.content_document.as_deref() {
        if let Some(node_id) = find_checkbox_node(document) {
            return Some(node_id);
        }
    }
    None
}

fn is_turnstile_response_input(node: &chaser_oxide::cdp::browser_protocol::dom::Node) -> bool {
    node.node_name.eq_ignore_ascii_case("input")
        && attribute(node, "name") == Some("cf-turnstile-response")
}

fn is_turnstile_iframe(node: &chaser_oxide::cdp::browser_protocol::dom::Node) -> bool {
    if !node.node_name.eq_ignore_ascii_case("iframe") {
        return false;
    }

    attribute(node, "id").is_some_and(|id| id.starts_with("cf-chl-widget-"))
        || attribute(node, "src").is_some_and(|src| {
            src.contains("challenges.cloudflare.com") && src.contains("turnstile")
        })
}

fn attribute<'a>(
    node: &'a chaser_oxide::cdp::browser_protocol::dom::Node,
    name: &str,
) -> Option<&'a str> {
    node.attributes
        .as_deref()
        .unwrap_or(&[])
        .chunks_exact(2)
        .find(|pair| pair[0].eq_ignore_ascii_case(name))
        .map(|pair| pair[1].as_str())
}

const TURNSTILE_EXTRACTOR_SCRIPT: &str = r#"
    (function() {
        let token = null;
        async function waitForToken() {
            while (!token) {
                try { token = window.turnstile.getResponse(); } catch(e) {}
                await new Promise(r => setTimeout(r, 500));
            }
            var c = document.createElement("input");
            c.type = "hidden"; c.name = "cf-response"; c.value = token;
            document.body.appendChild(c);
        }
        waitForToken();
    })();
"#;

async fn wait_for_turnstile_token(
    page: &chaser_oxide::Page,
    timeout_seconds: u64,
) -> ChaserResult<String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_seconds);
    let chaser = chaser_oxide::ChaserPage::new(page.clone());

    loop {
        if start.elapsed() > timeout {
            return Err(ChaserError::CaptchaFailed(
                "timeout waiting for token".into(),
            ));
        }

        let result = chaser
            .evaluate(
                r#"(function() {
                    if (window.turnstile && typeof window.turnstile.getResponse === 'function') {
                        var t = window.turnstile.getResponse();
                        if (t) return t;
                    }
                    var el = document.querySelector('[name="cf-response"]');
                    return el ? el.value : null;
                })()"#,
            )
            .await;

        if let Ok(Some(v)) = result {
            if let Some(t) = v.as_str() {
                if t.len() > 10 {
                    return Ok(t.to_string());
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::find_challenge_target;
    use chaser_oxide::cdp::browser_protocol::dom::{BackendNodeId, Node, NodeId};

    fn node(id: i64, name: &str, attributes: &[&str]) -> Node {
        Node::builder()
            .node_id(NodeId::new(id))
            .backend_node_id(BackendNodeId::new(id))
            .node_type(1)
            .node_name(name)
            .local_name(name.to_ascii_lowercase())
            .node_value("")
            .attributes(attributes.iter().copied())
            .build()
            .expect("valid test node")
    }

    fn dumped_challenge_tree(content_document: Option<Node>) -> Node {
        let mut iframe = Node::builder()
            .node_id(NodeId::new(4))
            .backend_node_id(BackendNodeId::new(4))
            .node_type(1)
            .node_name("IFRAME")
            .local_name("iframe")
            .node_value("")
            .attributes([
                "id",
                "cf-chl-widget-9uekg",
                "src",
                "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/turnstile/widget",
            ]);
        if let Some(document) = content_document {
            iframe = iframe.content_document(document);
        }
        let iframe = iframe.build().expect("valid iframe node");

        let shadow_root = node(3, "#document-fragment", &[]);
        let shadow_root = Node::builder()
            .node_id(shadow_root.node_id)
            .backend_node_id(shadow_root.backend_node_id)
            .node_type(shadow_root.node_type)
            .node_name(shadow_root.node_name)
            .local_name(shadow_root.local_name)
            .node_value(shadow_root.node_value)
            .children(iframe)
            .build()
            .expect("valid shadow root");

        let shadow_host = Node::builder()
            .node_id(NodeId::new(2))
            .backend_node_id(BackendNodeId::new(2))
            .node_type(1)
            .node_name("DIV")
            .local_name("div")
            .node_value("")
            .shadow_root(shadow_root)
            .build()
            .expect("valid shadow host");
        let response = node(
            5,
            "INPUT",
            &["type", "hidden", "name", "cf-turnstile-response"],
        );

        Node::builder()
            .node_id(NodeId::new(1))
            .backend_node_id(BackendNodeId::new(1))
            .node_type(1)
            .node_name("DIV")
            .local_name("div")
            .node_value("")
            .childrens([shadow_host, response])
            .build()
            .expect("valid response container")
    }

    #[test]
    fn locates_iframe_when_response_input_is_its_shadow_host_sibling() {
        let tree = dumped_challenge_tree(None);
        let target = find_challenge_target(&tree).expect("challenge target");

        assert_eq!(*target.iframe_node_id.inner(), 4);
        assert!(target.checkbox_node_id.is_none());
    }

    #[test]
    fn prefers_checkbox_inside_iframe_content_document() {
        let checkbox = node(7, "INPUT", &["type", "checkbox"]);
        let document = Node::builder()
            .node_id(NodeId::new(6))
            .backend_node_id(BackendNodeId::new(6))
            .node_type(9)
            .node_name("#document")
            .local_name("")
            .node_value("")
            .children(checkbox)
            .build()
            .expect("valid frame document");
        let tree = dumped_challenge_tree(Some(document));
        let target = find_challenge_target(&tree).expect("challenge target");

        assert_eq!(*target.iframe_node_id.inner(), 4);
        assert_eq!(target.checkbox_node_id.map(|id| *id.inner()), Some(7));
    }
}
