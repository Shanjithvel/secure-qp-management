/**
 * Authentication & 2FA OTP Management
 */

let currentUser = null;

async function handleLogin(e) {
  if (e) e.preventDefault();
  
  const usernameInput = document.getElementById('loginUsername').value.trim();
  const passwordInput = document.getElementById('loginPassword').value.trim();
  const alertBox = document.getElementById('loginAlert');
  alertBox.style.display = 'none';

  if (!usernameInput || !passwordInput) {
    showAlert(alertBox, 'Please enter both username and password.');
    return;
  }

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: usernameInput, password: passwordInput })
    });
    
    const data = await res.json();
    
    if (!res.ok) {
      showAlert(alertBox, data.detail || 'Login failed.');
      return;
    }

    if (data.status === 'MFA_REQUIRED') {
      // Show 2FA OTP Modal
      document.getElementById('otpUsername').value = data.username;
      document.getElementById('otpSimulatedNotice').innerText = `🔐 Demo 2FA OTP Code: ${data.simulated_otp}`;
      document.getElementById('otpModal').classList.add('active');
    }
  } catch (err) {
    showAlert(alertBox, 'Network connection error: ' + err.message);
  }
}

async function handleVerifyOTP(e) {
  if (e) e.preventDefault();
  
  const username = document.getElementById('otpUsername').value;
  const otpCode = document.getElementById('otpCodeInput').value.trim();
  const alertBox = document.getElementById('otpAlert');
  alertBox.style.display = 'none';

  if (!otpCode) {
    showAlert(alertBox, 'Please enter 6-digit OTP code.');
    return;
  }

  try {
    const res = await fetch('/api/auth/verify-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, otp_code: otpCode })
    });
    
    const data = await res.json();
    
    if (!res.ok) {
      showAlert(alertBox, data.detail || 'OTP Verification failed.');
      return;
    }

    currentUser = data;
    document.getElementById('otpModal').classList.remove('active');
    document.getElementById('loginCard').style.display = 'none';
    document.getElementById('authenticatedWorkspace').style.display = 'block';
    document.getElementById('workspaceContent').style.display = 'block';
    
    // Update User Profile Bar
    document.getElementById('navUserFullName').innerText = data.full_name;
    document.getElementById('navUserRole').innerText = data.role.toUpperCase();
    
    // Switch to default role tab
    switchRoleTab(data.role);
    refreshAllData();

  } catch (err) {
    showAlert(alertBox, 'OTP Verification Error: ' + err.message);
  }
}

function handleLogout() {
  currentUser = null;
  document.getElementById('authenticatedWorkspace').style.display = 'none';
  document.getElementById('workspaceContent').style.display = 'none';
  document.getElementById('loginCard').style.display = 'block';
  document.getElementById('loginPassword').value = '';
}

function showAlert(element, text) {
  element.innerText = text;
  element.style.display = 'block';
}

function quickSelectUser(username, password) {
  document.getElementById('loginUsername').value = username;
  document.getElementById('loginPassword').value = password;
}
