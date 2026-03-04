(() => {
  const PARAM_NAME = "auth-token";

  let token = null;
  try {
    token = new URL(window.location.href).searchParams.get(PARAM_NAME);
  } catch (err) {
    return;
  }

  if (!token) {
    return;
  }

  const originalFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    try {
      if (typeof input === "string") {
        const url = new URL(input, window.location.origin);
        if (url.pathname === "/auth/login_flow" && !url.searchParams.has(PARAM_NAME)) {
          url.searchParams.set(PARAM_NAME, token);
          return originalFetch(url.toString(), init);
        }
      } else if (input instanceof Request) {
        const url = new URL(input.url, window.location.origin);
        if (url.pathname === "/auth/login_flow" && !url.searchParams.has(PARAM_NAME)) {
          url.searchParams.set(PARAM_NAME, token);
          return originalFetch(new Request(url.toString(), input), init);
        }
      }
    } catch (err) {
      // Fall through to original request if URL handling fails.
    }

    return originalFetch(input, init);
  };
})();

