// Ensure global namespace exists immediately
window.XAYTHEON_AUTH = window.XAYTHEON_AUTH || {};

(function () {
  // Define API URL once
  const API_BASE_URL = "http://127.0.0.1:5000/api/auth";

  const REQUEST_TIMEOUT = 30000;

  async function fetchWithTimeout(resource, options = {}) {
    const { timeout = REQUEST_TIMEOUT } = options;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(resource, {
        ...options,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      return response;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === "AbortError") {
        throw { code: "TIMEOUT" };
      }
      throw err;
    }
  }

  let accessToken = null;
  let currentUser = null;
  let tokenExpiryTime = null;
  let refreshTimer = null;
  let lastAuthError = null;

  function isTokenExpired() {
    if (!tokenExpiryTime) return true;
    return Date.now() >= tokenExpiryTime;
  }

  function setAccessToken(token, expiresIn, user) {
    accessToken = token;
    currentUser = user || null;
    tokenExpiryTime = Date.now() + (expiresIn * 1000);
    scheduleTokenRefresh();

    window.dispatchEvent(
      new CustomEvent("xaytheon:authchange", { detail: { user: currentUser } })
    );
  }

  function getSession() {
    return {
      user: currentUser,
      accessToken: accessToken,
    };
  }

  function clearAccessToken() {
    accessToken = null;
    currentUser = null;
    tokenExpiryTime = null;
    localStorage.removeItem("x_refresh_token");

    if (refreshTimer) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }

    window.dispatchEvent(
      new CustomEvent("xaytheon:authchange", {
        detail: { user: null },
      })
    );
  }

  function scheduleTokenRefresh() {
    if (refreshTimer) clearTimeout(refreshTimer);
    if (!tokenExpiryTime) return;
    refreshTimer = setTimeout(refreshAccessToken, tokenExpiryTime - Date.now());
  }

  async function refreshAccessToken() {
    try {
      const storedRefreshToken = localStorage.getItem("x_refresh_token");

      let options = {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      };

      if (storedRefreshToken) {
        options.body = JSON.stringify({ refreshToken: storedRefreshToken });
      } else {
        options.credentials = "include"; // Try cookie
      }

      const res = await fetchWithTimeout(`${API_BASE_URL}/refresh`, options);

      if (!res.ok) throw { code: "SESSION_EXPIRED" };

      const data = await res.json();
      setAccessToken(data.accessToken, data.expiresIn, data.user);

      if (data.refreshToken) {
        localStorage.setItem("x_refresh_token", data.refreshToken);
      }

      return true;
    } catch (err) {
      // console.warn("Session restore failed:", err);
      clearAccessToken();
      return false;
    }
  }

  async function authenticatedFetch(url, options = {}) {
    if (isTokenExpired()) {
      const refreshed = await refreshAccessToken();
      if (!refreshed) {
        clearAccessToken();
        throw { code: "SESSION_EXPIRED" };
      }
    }

    const res = await fetchWithTimeout(url, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (res.status === 401) throw { code: "UNAUTHORIZED" };
    return res;
  }

  async function login(email, password) {
    if (!email || !password) throw { code: "INVALID_INPUT" };

    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      if (!res.ok) {
        let errorMessage = "Login failed";
        try {
          const err = await res.json();
          errorMessage = err.message || errorMessage;
        } catch {
          errorMessage = res.statusText || errorMessage;
        }
        throw new Error(errorMessage);
      }

      const data = await res.json();
      setAccessToken(data.accessToken, data.expiresIn, data.user);

      if (data.refreshToken) {
        localStorage.setItem("x_refresh_token", data.refreshToken);
      }

      // Fetch preferences after login
      await fetchPreferences();

    } catch (err) {
      if (err.message?.includes("Failed to fetch")) {
        throw { code: "NETWORK_ERROR" };
      }
      throw err;
    }
  }

  async function register(email, password) {
    if (!email || !password) throw { code: "INVALID_INPUT" };

    try {
      const res = await fetchWithTimeout(`${API_BASE_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      if (!res.ok) {
        if (res.status === 409) throw { code: "USER_EXISTS" };
        if (res.status === 429) throw { code: "TOO_MANY_ATTEMPTS" };
        if (res.status >= 500) throw { code: "SERVER_ERROR" };
        
        // Try to parse detailed error message
        let errorMessage = "Registration failed";
        try {
          const err = await res.json();
          errorMessage = err.message || errorMessage;
        } catch { }
        throw new Error(errorMessage);
      }

      return await res.json();
    } catch (err) {
      if (err.message?.includes("Failed to fetch")) {
        throw { code: "NETWORK_ERROR" };
      }
      throw err;
    }
  }

  async function savePreferences(preferences) {
    if (!accessToken) return; // Silent fail if not logged in
    try {
      // Use authenticatedFetch but point to /api/user/preferences
      // Hacky URL replacement or just use full URL
      const userUrl = API_BASE_URL.replace('/auth', '/user');
      await authenticatedFetch(`${userUrl}/preferences`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(preferences),
      });
    } catch (err) {
      console.warn("Failed to save preferences:", err);
    }
  }

  async function fetchPreferences() {
    if (!accessToken) return null;
    try {
      const userUrl = API_BASE_URL.replace('/auth', '/user');
      const res = await authenticatedFetch(`${userUrl}/preferences`);
      if (res.ok) {
        const prefs = await res.json();
        // Dispatch event or just return
        return prefs;
      }
    } catch (err) {
      console.warn("Failed to fetch preferences:", err);
    }
    return null;
  }

  async function logout() {
    try {
      await fetchWithTimeout(`${API_BASE_URL}/logout`, { method: "POST" });
    } catch { }
    clearAccessToken();
    window.location.reload();
  }

  function getAccessToken() {
    return accessToken;
  }

  function isAuthenticated() {
    return !!accessToken;
  }

  // --- UI Helpers ---

  async function restoreSession() {
    if (localStorage.getItem("x_refresh_token")) {
      try {
        await refreshAccessToken();
        // Also fetch prefs on restore
        await fetchPreferences();
      } catch (err) {
        console.log("No existing session restored");
        lastAuthError = err.message;
        renderAuthArea();
      }
    }
  }

  function renderAuthArea() {
    const container = document.getElementById("auth-area");
    if (!container) return;

    if (!isAuthenticated()) {
      if (lastAuthError) {
        container.innerHTML = `
           <div style="display:flex; align-items:center; gap:10px;">
             <span style="color:#ef4444; font-size:11px; max-width:150px; line-height:1.2;">
               ${lastAuthError}
             </span>
             <a class="btn btn-outline" href="login.html">Sign in</a>
           </div>
         `;
      } else {
        container.innerHTML = '<a class="btn btn-outline" href="login.html">Sign in</a>';
      }
      return;
    }

    container.innerHTML = `
      <div class="user-menu">
        <button class="user-button" id="user-button">
          <span class="user-avatar">U</span>
          <span class="chev">▾</span>
        </button>
        <div class="user-dropdown" id="user-dropdown" hidden>
          <button class="dropdown-item" id="sign-out-btn">Sign out</button>
        </div>
      </div>
    `;

    const btn = document.getElementById("user-button");
    const dd = document.getElementById("user-dropdown");
    const signOutBtn = document.getElementById("sign-out-btn");

    if (btn && dd && signOutBtn) {
      btn.addEventListener("click", () => {
        dd.toggleAttribute("hidden");
      });
      signOutBtn.addEventListener("click", logout);
    }
  }

  function applyAuthGating() {
    const authed = isAuthenticated();
    document.querySelectorAll("[data-requires-auth]").forEach((el) => (el.style.display = authed ? "" : "none"));
    document.querySelectorAll("[data-requires-guest]").forEach((el) => (el.style.display = authed ? "none" : ""));
  }

  // --- Public API ---

  window.XAYTHEON_AUTH = {
    getSession,
    login,
    register,
    logout,
    authenticatedFetch,
    savePreferences,
    fetchPreferences,
    isAuthenticated,
    getAccessToken
  };

  // --- Init ---

  window.addEventListener("DOMContentLoaded", async () => {
    await restoreSession();
    renderAuthArea();
    applyAuthGating();
  });

  window.addEventListener("beforeunload", () => {
    // Optional cleanup
  });

  // Attach additional methods (Forgot Password, etc.)

  window.XAYTHEON_AUTH.forgotPassword = async function (email) {
    // ... existing logic simplified for brevity or re-included if needed
    // Assuming full overwrite, I'll include the original simplified
    try {
      const response = await fetch(`${API_BASE_URL}/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Failed to send reset email");
      return data;
    } catch (error) {
      console.error("Forgot password error:", error);
      throw error;
    }
  };

  window.XAYTHEON_AUTH.resetPassword = async function (token, newPassword) {
    try {
      const response = await fetch(`${API_BASE_URL}/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, newPassword }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Failed to reset password");
      return data;
    } catch (error) {
      console.error("Reset password error:", error);
      throw error;
    }
  };

  window.XAYTHEON_AUTH.validateResetToken = async function (token) {
    try {
      const response = await fetch(`${API_BASE_URL}/validate-reset-token?token=${encodeURIComponent(token)}`, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });
      const data = await response.json();
      if (!response.ok || !data.valid) throw new Error(data.message || "Invalid token");
      return data;
    } catch (error) {
      console.error("Validate token error:", error);
      throw error;
    }
  };

})();

function getAuthErrorMessage(error) {
  if (!error) return "Something went wrong. Please try again.";
  if (error.message === "Failed to fetch") return "Network error. Please check your internet connection.";
  switch (error.code) {
    case "INVALID_CREDENTIALS": return "Invalid email or password.";
    case "USER_EXISTS": return "User already exists. Please log in.";
    case "UNAUTHORIZED": return "You are not authorized. Please login again.";
    case "SESSION_EXPIRED": return "Your session has expired. Please login again.";
    default: return error.message || "Authentication failed.";
  }
}
