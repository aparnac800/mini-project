document.addEventListener('DOMContentLoaded', () => {
    const artworksContainer = document.getElementById('artworks-container');
    const editArtworkModal = new bootstrap.Modal(document.getElementById('editArtworkModal'));
    const artworkDetailModal = new bootstrap.Modal(document.getElementById('artworkDetailModal'));
    const cartModal = new bootstrap.Modal(document.getElementById('cartModal'));
    const uploadArtworkModal = new bootstrap.Modal(document.getElementById('uploadArtworkModal'));
    // Since the frontend and backend are served from the same origin,
    // we can use a relative path. This makes the app more portable.
    // All fetch requests will now be relative to the current domain (e.g., '/api/artworks').
    const API_BASE_URL = '';

    // --- Initialize Session FIRST ---
    // Global variables to store user info and token
    let currentUser = null;

    /**
     * Centralized function to initialize or clear the user session.
     * This is the single source of truth for the app's auth state.
     */
    function initializeSession() {
        const storedToken = localStorage.getItem('jwt_token');
        const storedUser = localStorage.getItem('current_user'); // We can still use this for quick UI updates

        // With sessions, we can't be 100% sure the user is logged in just from localStorage.
        // But we can use the stored user data for an optimistic UI update on page load.
        // The server will be the ultimate source of truth on the first authenticated request.
        try {
            if (storedUser && storedUser !== 'null') {
                currentUser = JSON.parse(storedUser);
            } else {
                currentUser = null;
            }
        } catch (e) {
            // If user data is corrupted, clear it.
            console.error("Corrupted user data in localStorage. Clearing session.", e);
            localStorage.removeItem('current_user');
            currentUser = null;
        }

        // Update the UI based on the potentially logged-in user
        updateUIForLoginStatus();

        // Now that the session is initialized and UI is updated, handle the initial route.
        handleHashChange();
    }

    /**
     * A helper function to make authenticated fetch requests.
     * It centralizes token handling, content type, and basic error processing.
     * @param {string} url - The URL to fetch.
     * @param {object} options - The options for the fetch call (method, body, etc.).
     * @returns {Promise<any>} - The JSON response from the server.
     */
    async function fetchWithAuth(url, options = {}) {
        const headers = new Headers({
            ...options.headers,
        });

        // Do not set Content-Type for FormData, the browser does it with the correct boundary.
        if (!(options.body instanceof FormData)) {
            headers.set('Content-Type', 'application/json');
        }

        const response = await fetch(url, { ...options, headers });

        // --- Global Error Handling for Authentication ---
        // If the response is a 401 Unauthorized, it's a strong signal that the JWT is
        // expired, invalid, or malformed. Instead of letting every function handle this,
        // we catch it here, log the user out, and force a clean session. This prevents
        // the user from being stuck in a broken state.
        if (response.status === 401) {
            console.warn("Received 401 Unauthorized. Session may be invalid or expired. Logging out.");
            // Clear local user data and reload to show the logged-out state.
            // The server-side session is already invalid.
            currentUser = null;
            localStorage.removeItem('current_user');
            localStorage.removeItem('jwt_token'); // Clean up old token
            window.location.reload();
            throw new Error("Your session has expired. You have been logged out."); // Prevent further execution
        }

        if (!response.ok) {
            // Try to parse the error response as JSON, but handle cases where it's HTML.
            let errorMessage = `Request failed with status ${response.status}`;
            try {
                const errorData = await response.json();
                errorMessage = errorData.message || errorMessage;
            } catch (e) {
                // The error response was not JSON (likely HTML), so we use the status text.
                errorMessage = `${response.status}: ${response.statusText}`;
            }
            throw new Error(errorMessage);
        }
        return response.json(); // Parse and return JSON only on success.
    }

    // --- Authentication ---

    // Helper function to display messages in auth forms (login, register, upload)
    function showAuthMessage(formId, message, isError = false) {
        const form = document.getElementById(formId);
        const parentContainer = form.closest('.modal-body') || form;

        let messageEl = form.querySelector('.auth-message');
        if (!messageEl) {
            messageEl = document.createElement('div');
            messageEl.className = 'auth-message mt-3';
            if (formId === 'uploadForm' && parentContainer.classList.contains('modal-body')) {
                parentContainer.prepend(messageEl);
            } else {
                form.prepend(messageEl);
            }
        }
        messageEl.textContent = message;
        messageEl.className = `auth-message mt-3 text-center ${isError ? 'text-danger' : 'text-success'}`;
    }

    // Helper function to handle successful login or registration
    function handleAuthSuccess(data, formId, message) {
        // 1. Update the live application state
        currentUser = data.user;
        localStorage.setItem('current_user', JSON.stringify(data.user));

        // 3. Show a success message to the user
        const modalElement = document.getElementById('loginRegisterModal');
        // Get the existing instance or create a new one to ensure it's never null
        const modalInstance = bootstrap.Modal.getInstance(modalElement) || new bootstrap.Modal(modalElement);
        showAuthMessage(formId, message);
        
        // 4. After a short delay, hide the modal and navigate the user
        setTimeout(() => {
            modalInstance.hide(); // Hide the modal

            // Reset the form and clear the message
            document.querySelector(`#${formId}`).reset();
            const messageEl = document.querySelector(`#${formId} .auth-message`);
            if (messageEl) messageEl.textContent = '';
            // Now that the state is updated in memory, we can navigate directly to the profile page.
            // The handleHashChange function will then correctly fetch all necessary data.
            window.location.hash = 'profile';
        }, 1000);
    }

    // Handle user logout
    function handleLogout() {
        // Call the new server endpoint to destroy the session
        fetchWithAuth(`${API_BASE_URL}/api/logout`, { method: 'POST' })
            .then(() => {
                // On success, clear local data and reload the page
                currentUser = null;
                localStorage.removeItem('current_user');
                localStorage.removeItem('jwt_token'); // Clean up old token if it exists
                window.location.reload();
            }).catch(error => {
                alert(`Logout failed: ${error.message}. Forcing reload.`);
                window.location.reload(); // Force reload even if logout API fails
            });
    }

    // Event listener for the registration form
    document.getElementById('registerForm').addEventListener('submit', async function(event) {
        event.preventDefault();
        const form = event.target;
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;

        const username = document.getElementById('registerUsername').value.trim();
        const email = document.getElementById('registerEmail').value.trim();
        const password = document.getElementById('registerPassword').value.trim();
        const role = document.getElementById('registerRole').value;

        if (!username || !email || !password) {
            showAuthMessage('registerForm', 'Please fill out all fields.', true);
            return;
        }
        if (!/\S+@\S+\.\S+/.test(email)) {
            showAuthMessage('registerForm', 'Please enter a valid email address.', true);
            return;
        }
        if (password.length < 6) {
            showAuthMessage('registerForm', 'Password must be at least 6 characters long.', true);
            return;
        }
        if (!role) {
            showAuthMessage('registerForm', 'Please select a role.', true);
            return;
        }

        submitButton.disabled = true;
        submitButton.innerHTML = `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Registering...`;

        try {
            const data = await fetchWithAuth(`${API_BASE_URL}/api/register`, {
                method: 'POST',
                body: JSON.stringify({ username, email, password, role: role.toLowerCase() })
            });
            handleAuthSuccess(data, 'registerForm', 'Registration successful! Logging you in...');
        } catch (error) {
            console.error('Registration error:', error);
            showAuthMessage('registerForm', error.message, true);
        } finally {
            submitButton.disabled = false;
            submitButton.innerHTML = originalButtonText;
        }
    });

    // Event listener for the login form
    document.getElementById('loginForm').addEventListener('submit', async function(event) {
        event.preventDefault();
        const form = event.target;
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;

        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        submitButton.disabled = true;
        submitButton.innerHTML = `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Signing In...`;

        try {
            const data = await fetchWithAuth(`${API_BASE_URL}/api/login`, {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
            handleAuthSuccess(data, 'loginForm', 'Login successful!');

        } catch (error) {
            console.error('Login error:', error);
            showAuthMessage('loginForm', error.message, true);
        } finally {
            // Always restore the button state. On success, the UI flow is handled
            // by handleAuthSuccess, but on error, this ensures the user can try again.
            submitButton.disabled = false;
            submitButton.innerHTML = originalButtonText;
        }
    });

    // Event listener for the "Forgot Password" link
    document.getElementById('forgotPasswordLink').addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('pills-login').classList.remove('show', 'active');
        document.getElementById('pills-forgot').classList.add('show', 'active');
    });

    // Event listener for the "Back to Login" link
    document.getElementById('backToLoginLink').addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('pills-forgot').classList.remove('show', 'active');
        document.getElementById('pills-login').classList.add('show', 'active');
    });

    // Handle forgot password form submission
    document.getElementById('forgotPasswordForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('forgotEmail').value;
        try {
            const data = await fetchWithAuth(`${API_BASE_URL}/api/forgot-password`, {
                method: 'POST',
                body: JSON.stringify({ email })
            });
            showAuthMessage('forgotPasswordForm', data.message, false);
        } catch (error) {
            showAuthMessage('forgotPasswordForm', error.message, true);
        }
    });

    // Handle reset password form submission
    document.getElementById('resetPasswordForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const token = document.getElementById('resetTokenInput').value;
        const password = document.getElementById('resetNewPassword').value;
        try {
            const data = await fetchWithAuth(`${API_BASE_URL}/api/reset-password`, {
                method: 'POST',
                body: JSON.stringify({ token, password })
            });
            alert(data.message);
            window.location.hash = ''; // Clear hash
            window.location.reload(); // Reload to go back to the main page
        } catch (error) {
            alert(`Error: ${error.message}`);
        }
    });

    // Function to update UI based on login status
    function updateUIForLoginStatus() {
        // Get references to navigation elements inside this function
        // to ensure they are always available when the function is called.
        const loginRegisterNavLink = document.getElementById('loginRegisterNavLink');
        const uploadArtworkNavLink = document.getElementById('uploadArtworkNavLink');
        const myArtworksNavLink = document.getElementById('myArtworksNavLink');
        const logoutNavLink = document.getElementById('logoutNavLink');
        const orderHistoryNavLink = document.getElementById('orderHistoryNavLink');
        const salesDashboardNavLink = document.getElementById('salesDashboardNavLink');
        const cartNavLink = document.getElementById('cartNavLink');
        const profileNavLink = document.getElementById('profileNavLink');
        const adminDashboardNavLink = document.getElementById('adminDashboardNavLink');
        if (currentUser) { // The check is now just for the presence of a user object
            const isArtist = currentUser.role === 'artist';
            const isBuyer = currentUser.role === 'buyer';
            const isAdmin = currentUser.role === 'admin';

            // A helper to safely show/hide elements
            const toggleElement = (element, shouldShow) => {
                if (element) element.style.display = shouldShow ? 'block' : 'none';
            };

            toggleElement(loginRegisterNavLink, false);
            toggleElement(uploadArtworkNavLink, isArtist);
            toggleElement(myArtworksNavLink, isArtist);
            toggleElement(salesDashboardNavLink, isArtist);
            toggleElement(adminDashboardNavLink, isAdmin);
            toggleElement(orderHistoryNavLink, isBuyer); // Only show order history to buyers
            toggleElement(profileNavLink, true);
            toggleElement(logoutNavLink, true);
            toggleElement(cartNavLink, true);
            // The badge is now updated by functions that fetch cart data, like fetchCartItems.
        } else {
            if (loginRegisterNavLink) loginRegisterNavLink.style.display = 'block';
            if (uploadArtworkNavLink) uploadArtworkNavLink.style.display = 'none';
            if (myArtworksNavLink) myArtworksNavLink.style.display = 'none';
            if (salesDashboardNavLink) salesDashboardNavLink.style.display = 'none';
            if (adminDashboardNavLink) adminDashboardNavLink.style.display = 'none';
            if (orderHistoryNavLink) orderHistoryNavLink.style.display = 'none';
            if (profileNavLink) profileNavLink.style.display = 'none';
            if (logoutNavLink) logoutNavLink.style.display = 'none';
            if (cartNavLink) cartNavLink.style.display = 'none';
        }
    }

    // Function to render artwork cards (used for main gallery and my artworks)
    function renderArtworks(artworksToRender, targetContainer = artworksContainer, options = {}) {
        const { showManagementButtons = false } = options;
        targetContainer.innerHTML = ''; 
        const galleryTitle = document.getElementById('gallery-title');

        if (artworksToRender.length === 0) {
            targetContainer.innerHTML = `<div class="col-12 text-center py-5"><p class="text-muted fs-5">No artworks found.</p></div>`;
            if (galleryTitle) galleryTitle.style.display = 'none'; // Hide title if no artworks
            return;
        }

        if (galleryTitle) galleryTitle.style.display = 'block'; // Show title if there are artworks

        artworksToRender.forEach(artwork => {
            const artistName = artwork.artist ? artwork.artist.username : 'Unknown Artist';
            
            // Conditionally add management buttons (like Delete)
            const managementButtons = showManagementButtons ? `
                <button class="btn btn-sm btn-outline-secondary rounded-pill me-2 edit-artwork-btn" data-id="${artwork.id}">
                    <i class="fas fa-edit me-1"></i>Edit
                </button>
                <button class="btn btn-sm btn-outline-danger rounded-pill delete-artwork-btn" data-id="${artwork.id}">
                    <i class="fas fa-trash-alt me-1"></i>Delete
                </button>
            ` : '';

            const artworkCard = `
                <div class="col artwork-card">
                    <div class="card h-100 shadow-sm" data-id="${artwork.id}">
                        <img src="${artwork.image_url}" class="card-img-top object-fit-cover" alt="${artwork.title}" style="height: 200px;">
                        <div class="card-body d-flex flex-column">
                            <h5 class="card-title">${artwork.title}</h5>
                            ${!showManagementButtons ? `<p class="card-text text-muted mb-1">by ${artistName}</p>` : ''}
                            <p class="card-text text-muted mb-3">${artwork.category}</p>
                            <div class="mt-auto d-flex justify-content-between align-items-center">
                                <span class="artwork-price">$${artwork.price.toFixed(2)}</span>
                                ${managementButtons}
                                <button class="btn btn-sm btn-outline-primary rounded-pill view-details-btn" data-id="${artwork.id}">View Details</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            targetContainer.insertAdjacentHTML('beforeend', artworkCard);
        });
    }

    // Function to fetch all artworks from the API
    function fetchArtworks(searchTerm = '') {
        artworksContainer.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></div>';
        
        let url = `${API_BASE_URL}/api/artworks`;
        if (searchTerm) {
            url += `?search=${encodeURIComponent(searchTerm)}`;
        }

        fetch(url) // Public endpoint, no auth needed
            .then(response => response.ok ? response.json() : Promise.reject(response))
            .then(renderArtworks)
            .catch(error => {
                console.error('Error fetching artworks:', error.statusText || error);
                artworksContainer.innerHTML = '<p class="text-center text-danger">Failed to load artworks. Please ensure the backend server is running.</p>';
            });
    }

    // Function to fetch artworks for the logged-in artist
    function fetchMyArtworks() {
        // If we are not on the my-artworks page, this function doesn't need to run.
        if (window.location.pathname !== '/my-artworks') {
            return;
        }

        const myArtworksContainer = document.getElementById('my-artworks-container');
        myArtworksContainer.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></div>';

        fetchWithAuth(`${API_BASE_URL}/api/my-artworks`)
            .then(data => {
                // Reuse renderArtworks, passing the specific container and enabling management buttons
                renderArtworks(data, myArtworksContainer, { showManagementButtons: true });
            })
            .catch(error => {
                console.error('Error fetching my artworks:', error);
                myArtworksContainer.innerHTML = `<p class="text-center text-danger">${error.message || 'Failed to load your artworks. Please try logging in again.'}</p>`;
            });
    }

    // Function to fetch and render order history
    function fetchOrderHistory() {
        const container = document.getElementById('order-history-container');
        container.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></div>';

        fetchWithAuth(`${API_BASE_URL}/api/orders`)
            .then(orders => { // The data is the array of orders
                if (orders.length === 0) {
                    container.innerHTML = '<p class="text-center text-muted">You have not placed any orders yet.</p>';
                    return;
                }

                container.innerHTML = '';
                orders.forEach(order => {
                    const orderDate = new Date(order.order_date).toLocaleDateString();
                    const itemsHtml = order.items.map(item => `
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="my-0">${item.artwork.title}</h6>
                                <small class="text-muted">by ${item.artwork.artist.username}</small>
                            </div>
                            <span class="text-muted">$${item.price_at_purchase.toFixed(2)}</span>
                        </li>
                    `).join('');

                    const orderElement = `
                        <div class="accordion-item">
                            <h2 class="accordion-header" id="heading-${order.id}">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-${order.id}">
                                    Order #${order.id} - Placed on ${orderDate} - Total: $${order.total_amount.toFixed(2)}
                                </button>
                            </h2>
                            <div id="collapse-${order.id}" class="accordion-collapse collapse" data-bs-parent="#order-history-container">
                                <div class="accordion-body">
                                    <ul class="list-group mb-3">${itemsHtml}</ul>
                                </div>
                            </div>
                        </div>
                    `;
                    container.insertAdjacentHTML('beforeend', orderElement);
                });
            })
            .catch(error => {
                console.error('Error fetching order history:', error);
                container.innerHTML = `<p class="text-center text-danger">${error.message || 'Failed to load your order history.'}</p>`;
            });
    }

    // Function to fetch and render artist's sales data
    function fetchSalesDashboard() {
        const container = document.getElementById('sales-dashboard-container');
        const summaryContainer = document.getElementById('sales-dashboard-summary');
        const tableBody = document.querySelector('#sales-dashboard-container tbody');
        const tableHead = document.querySelector('#sales-dashboard-container thead');
        
        tableBody.innerHTML = '<tr><td colspan="5" class="text-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></td></tr>';
        summaryContainer.innerHTML = '';

        fetchWithAuth(`${API_BASE_URL}/api/artist/sales`)
            .then(sales => { // The data is the array of sales
                if (sales.length === 0) {
                    tableHead.innerHTML = ''; // Clear header if no sales
                    tableBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">You have not made any sales yet.</td></tr>';
                    return;
                }

                // Render table header
                tableHead.innerHTML = `
                    <tr>
                        <th scope="col">Artwork</th>
                        <th scope="col">Order ID</th>
                        <th scope="col">Date Sold</th>
                        <th scope="col">Customer</th>
                        <th scope="col" class="text-end">Sale Price</th>
                    </tr>
                `;

                // Render table rows and calculate summaries
                let totalRevenue = 0;
                tableBody.innerHTML = '';
                sales.forEach(sale => {
                    totalRevenue += sale.sale_price;
                    tableBody.innerHTML += `
                        <tr>
                            <td>
                                <div class="d-flex align-items-center">
                                    <img src="${sale.artwork_image_url}" width="50" class="rounded me-3">
                                    <span>${sale.artwork_title}</span>
                                </div>
                            </td>
                            <td>#${sale.order_id}</td>
                            <td>${new Date(sale.order_date).toLocaleDateString()}</td>
                            <td>${sale.customer.username}</td>
                            <td class="text-end text-success fw-bold">$${sale.sale_price.toFixed(2)}</td>
                        </tr>
                    `;
                });

                // Render summary cards
                summaryContainer.innerHTML = `
                    <div class="col-md-6"><div class="card card-body text-center shadow-sm"><h5>Total Sales</h5><p class="fs-4 mb-0">${sales.length}</p></div></div>
                    <div class="col-md-6"><div class="card card-body text-center shadow-sm"><h5>Total Revenue</h5><p class="fs-4 text-success mb-0">$${totalRevenue.toFixed(2)}</p></div></div>
                `;
            })
            .catch(error => {
                console.error('Error fetching sales dashboard:', error);
                tableBody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">${error.message || 'Failed to load your sales dashboard.'}</td></tr>`;
            });
    }

    // Function to fetch and render profile data
    function fetchProfileData() {
        const usernameInput = document.getElementById('profileUsername');
        const emailInput = document.getElementById('profileEmail');
        const roleSpecificTitle = document.getElementById('role-specific-title');
        const roleSpecificContent = document.getElementById('role-specific-content');

        // Clear previous content and show loading state
        roleSpecificTitle.style.display = 'none';
        roleSpecificContent.innerHTML = '<div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div>';

        fetchWithAuth(`${API_BASE_URL}/api/profile`)
            .then(user => {
                usernameInput.value = user.username;
                emailInput.value = user.email;
                usernameInput.placeholder = user.username; // Set placeholder for visual cue

                // Now fetch role-specific data
                if (user.role === 'artist') {
                    roleSpecificTitle.textContent = 'Artist Quick Stats';
                    roleSpecificTitle.style.display = 'block';
                    fetchWithAuth(`${API_BASE_URL}/api/artist/sales`)
                        .then(sales => {
                            const totalRevenue = sales.reduce((acc, sale) => acc + sale.sale_price, 0);
                            roleSpecificContent.innerHTML = `
                                <div class="col-md-4 mb-3"><div class="card card-body text-center shadow-sm h-100"><h5>Total Revenue</h5><p class="fs-4 text-success mb-0">$${totalRevenue.toFixed(2)}</p></div></div>
                                <div class="col-md-4 mb-3"><div class="card card-body text-center shadow-sm h-100"><h5>Total Sales</h5><p class="fs-4 mb-0">${sales.length}</p></div></div>
                                <div class="col-md-4 mb-3"><div class="card card-body text-center shadow-sm h-100 d-flex flex-column justify-content-center">
                                    <h5 class="card-title">Upload New Artwork</h5>
                                    <p class="card-text small text-muted">Add your latest creation to the gallery.</p>
                                    <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#uploadArtworkModal"><i class="fas fa-upload me-2"></i>Upload Now</button>
                                </div></div>
                            `;
                        });
                } else if (user.role === 'buyer') {
                    roleSpecificTitle.textContent = 'Buyer Activity';
                    roleSpecificTitle.style.display = 'block';
                    fetchWithAuth(`${API_BASE_URL}/api/orders`)
                        .then(orders => {
                            roleSpecificContent.innerHTML = `
                                <div class="col-md-6"><div class="card card-body text-center shadow-sm"><h5>Total Orders</h5><p class="fs-4 mb-0">${orders.length}</p></div></div>
                                <div class="col-md-6"><div class="card card-body text-center shadow-sm d-flex flex-column justify-content-center">
                                    <a href="#order-history" class="btn btn-outline-primary">View Order History</a>
                                </div></div>
                            `;
                        });
                } else {
                    // For any other roles or if no specific content is needed
                    roleSpecificContent.innerHTML = '';
                }
            })
            .catch(error => {
                console.error('Error fetching profile data:', error);
                roleSpecificContent.innerHTML = '<p class="text-danger">Could not load profile data.</p>';
            });
    }

    // Helper function to display messages within profile cards
    function showProfileMessage(formId, message, isError = false) {
        const form = document.getElementById(formId);
        const cardBody = form.closest('.card-body');
        let messageEl = cardBody.querySelector('.profile-message');
        if (!messageEl) {
            messageEl = document.createElement('div');
            messageEl.className = 'profile-message mt-3';
            form.insertAdjacentElement('afterend', messageEl);
        }
        messageEl.textContent = message;
        messageEl.className = `profile-message mt-3 text-center small ${isError ? 'text-danger' : 'text-success'}`;
        // Message will fade out after a few seconds if it's a success message
        if (!isError) setTimeout(() => { messageEl.textContent = ''; }, 3000);
    }

    // Handle profile update form submission
    document.getElementById('updateProfileForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const newUsername = document.getElementById('profileUsername').value;

        try {
            const data = await fetchWithAuth(`${API_BASE_URL}/api/profile`, {
                method: 'PUT',
                body: JSON.stringify({ username: newUsername })
            });
            // Update local storage with the new user data
            localStorage.setItem('current_user', JSON.stringify(data.user));
            currentUser = data.user;
            showProfileMessage('updateProfileForm', data.message, false);
        } catch (error) {
            showProfileMessage('updateProfileForm', `Error: ${error.message}`, true);
        }
    });

    // Handle change password form submission
    document.getElementById('changePasswordForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        const currentPassword = document.getElementById('currentPassword').value;
        const newPassword = document.getElementById('newPassword').value;

        try {
            const data = await fetchWithAuth(`${API_BASE_URL}/api/profile/change-password`, {
                method: 'POST',
                body: JSON.stringify({ currentPassword, newPassword })
            });
            showProfileMessage('changePasswordForm', data.message, false);
            form.reset();
        } catch (error) {
            showProfileMessage('changePasswordForm', `Error: ${error.message}`, true);
        }
    });

    // Function to display artwork details in modal
    function showArtworkDetails(id) {
        fetch(`${API_BASE_URL}/api/artworks/${id}`) // Public endpoint
            .then(response => response.ok ? response.json() : Promise.reject(response))
            .then(artwork => {
                const artistName = artwork.artist ? artwork.artist.username : 'Unknown Artist';
                document.getElementById('detailArtworkImage').src = artwork.image_url;
                document.getElementById('detailArtworkImage').alt = artwork.title;
                document.getElementById('detailArtworkTitle').textContent = artwork.title;
                document.getElementById('detailArtworkArtist').textContent = artistName;
                document.getElementById('detailArtworkCategory').textContent = artwork.category;
                document.getElementById('detailArtworkPrice').textContent = artwork.price.toFixed(2);
                document.getElementById('detailArtworkDescription').textContent = artwork.description;
                
                const purchaseActions = document.getElementById('purchase-actions');
                purchaseActions.style.display = (currentUser && currentUser.id !== artwork.artist_id) ? 'block' : 'none';
                document.getElementById('addToCartBtn').onclick = () => addToCart(artwork.id);
                document.getElementById('reviewArtworkId').value = id;
                document.getElementById('review-form-container').style.display = currentUser ? 'block' : 'none';
                fetchAndRenderReviews(id);
                artworkDetailModal.show();
            })
            .catch(error => console.error('Error fetching artwork details:', error.statusText || error));
    }

    // Function to fetch and render reviews for an artwork
    function fetchAndRenderReviews(artworkId) {
        const reviewsContainer = document.getElementById('reviews-container');
        reviewsContainer.innerHTML = '<p class="text-muted">Loading reviews...</p>';

        fetch(`${API_BASE_URL}/api/artworks/${artworkId}/reviews`) // Public endpoint
            .then(response => response.ok ? response.json() : Promise.reject(response))
            .then(reviews => {
                if (reviews.length === 0) {
                    reviewsContainer.innerHTML = '<p class="text-muted">No reviews yet. Be the first to leave one!</p>';
                    return;
                }

                reviewsContainer.innerHTML = ''; // Clear loading message
                reviews.forEach(review => {
                    const reviewDate = new Date(review.review_date).toLocaleDateString();
                    const reviewerName = review.user ? review.user.username : 'Anonymous';
                    
                    // Generate star icons based on rating
                    let stars = '';
                    for (let i = 1; i <= 5; i++) {
                        stars += `<i class="${i <= review.rating ? 'fas' : 'far'} fa-star text-warning"></i>`;
                    }

                    // Conditionally add Edit/Delete buttons if the current user is the author
                    let managementButtons = '';
                    if (currentUser && review.user && currentUser.id === review.user.id) {
                        managementButtons = `
                            <div class="review-actions ms-auto">
                                <button class="btn btn-sm btn-link text-secondary p-0 me-2 edit-review-btn" data-review-id="${review.id}" data-artwork-id="${artworkId}">Edit</button>
                                <button class="btn btn-sm btn-link text-danger p-0 delete-review-btn" data-review-id="${review.id}" data-artwork-id="${artworkId}">Delete</button>
                            </div>
                        `;
                    }

                    const reviewElement = `
                        <div class="mb-3 border-bottom pb-2" id="review-${review.id}">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <strong>${reviewerName}</strong>
                                    <small class="text-muted ms-2">${reviewDate}</small>
                                </div>
                                ${managementButtons}
                            </div>
                            <div class="my-1">${stars}</div>
                            <p class="mb-0">${review.comment || '<em>No comment provided.</em>'}</p>
                        </div>
                    `;
                    reviewsContainer.insertAdjacentHTML('beforeend', reviewElement);
                });
            })
            .catch(error => { // Catch block for fetchAndRenderReviews
                console.error('Error fetching reviews:', error);
                reviewsContainer.innerHTML = '<p class="text-danger">Could not load reviews.</p>';
            });
    }


    // Use event delegation for "View Details" buttons for better performance
    // A single listener on the body is more efficient and handles dynamically added content.
    document.body.addEventListener('click', function(event) {
        const viewBtn = event.target.closest('.view-details-btn');
        const deleteBtn = event.target.closest('.delete-artwork-btn');
        const editBtn = event.target.closest('.edit-artwork-btn');
        const removeCartBtn = event.target.closest('.remove-from-cart-btn');
        const deleteUserBtn = event.target.closest('.delete-user-btn');
        const updateStatusBtn = event.target.closest('.update-status-btn');
        const deleteReviewBtn = event.target.closest('.delete-review-btn');
        const editReviewBtn = event.target.closest('.edit-review-btn');

        if (viewBtn) {
            const artworkId = viewBtn.dataset.id;
            showArtworkDetails(artworkId);
            return;
        }

        if (deleteBtn) {
            const artworkId = deleteBtn.dataset.id;
            if (confirm('Are you sure you want to permanently delete this artwork? This action cannot be undone.')) {
                deleteArtwork(artworkId);
            }
            return;
        }

        if (editBtn) {
            const artworkId = editBtn.dataset.id;
            populateEditModal(artworkId);
            return;
        }

        if (removeCartBtn) {
            const itemId = removeCartBtn.dataset.itemId;
            fetchWithAuth(`${API_BASE_URL}/api/cart/item/${itemId}`, { method: 'DELETE' })
                .then(() => {
                    fetchCartItems(); // Refresh cart view and total
                })
                .catch(error => alert(`Error: ${error.message}`));
        }

        if (deleteUserBtn) {
            const userId = deleteUserBtn.dataset.userId;
            const username = deleteUserBtn.dataset.username;
            if (confirm(`Are you sure you want to permanently delete the user "${username}"? This will also delete all their artworks, orders, and reviews. This action cannot be undone.`)) {
                fetchWithAuth(`${API_BASE_URL}/api/admin/users/${userId}`, { method: 'DELETE' })
                    .then(data => {
                        alert(data.message);
                        // Remove the user's row from the table for immediate feedback
                        const userRow = document.getElementById(`user-row-${userId}`);
                        if (userRow) {
                            userRow.remove();
                        }
                    })
                    .catch(error => alert(`Error: ${error.message}`));
            }
        }

        if (updateStatusBtn) {
            event.preventDefault();
            const orderId = updateStatusBtn.dataset.orderId;
            const newStatus = updateStatusBtn.dataset.status;

            fetchWithAuth(`${API_BASE_URL}/api/admin/orders/${orderId}/status`, {
                method: 'PUT',
                body: JSON.stringify({ status: newStatus })
            })
            .then(data => {
                alert(data.message);
                // Update the status badge on the page for immediate feedback
                const statusBadge = document.getElementById(`status-badge-${orderId}`);
                if (statusBadge) {
                    statusBadge.textContent = newStatus;
                    // You can also change the badge color based on status
                }
            })
            .catch(error => alert(`Error: ${error.message}`));
        }

        if (deleteReviewBtn) {
            const reviewId = deleteReviewBtn.dataset.reviewId;
            const artworkId = deleteReviewBtn.dataset.artworkId;
            if (confirm('Are you sure you want to delete this review?')) {
                fetchWithAuth(`${API_BASE_URL}/api/reviews/${reviewId}`, { method: 'DELETE' })
                    .then(data => {
                        alert(data.message);
                        fetchAndRenderReviews(artworkId); // Refresh reviews list
                    })
                    .catch(error => alert(`Error: ${error.message}`));
            }
            return;
        }

        if (editReviewBtn) {
            // For now, we'll just log this. A full implementation would
            // replace the review text with an editable form.
            alert('Edit functionality is a great next step! This would involve replacing the review content with an inline form.');
            return;
        }
    });

    // Function to delete an artwork
    function deleteArtwork(artworkId) {
        fetchWithAuth(`${API_BASE_URL}/api/artworks/${artworkId}`, { method: 'DELETE' })
            .then(data => {
                alert(data.message);
                fetchMyArtworks(); // Refresh the list after successful deletion
            })
            .catch(error => {
                console.error('Error deleting artwork:', error);
                alert(`Error: ${error.message}`);
            });
    };

    // Function to populate the edit modal with artwork data
    function populateEditModal(artworkId) {
        // Fetch the specific artwork's details
        fetchWithAuth(`${API_BASE_URL}/api/artworks/${artworkId}`) // Use auth in case details differ for owner
            .then(artwork => {
                document.getElementById('editArtworkId').value = artwork.id;
                document.getElementById('editArtworkTitle').value = artwork.title;
                document.getElementById('editArtworkDescription').value = artwork.description;
                document.getElementById('editArtworkPrice').value = artwork.price;
                document.getElementById('editArtworkCategory').value = artwork.category;
                editArtworkModal.show();
            })
            .catch(error => { // Catch block for populateEditModal
                console.error('Error fetching artwork for edit:', error);
                alert('Could not load artwork details for editing.');
            });
    }

    // --- Shopping Cart Logic ---

    // Add item to cart
    function addToCart(artworkId) {
        fetchWithAuth(`${API_BASE_URL}/api/cart/add`, {
            method: 'POST',
            body: JSON.stringify({ artwork_id: artworkId })
        })
            .then(data => {
                alert(data.message);
                fetchCartItems(); // Refresh cart to update the badge count
                artworkDetailModal.hide();
            })
            .catch(error => alert(`Error: ${error.message}`));
    }

    // Fetch and display cart items
    function fetchCartItems(updateBadgeOnly = false) {
        // If the user is not logged in, there's nothing to fetch.
        if (!currentUser) return;

        const cartBody = document.getElementById('cart-body');
        const cartFooter = document.getElementById('cart-footer');
        cartBody.innerHTML = '<p>Loading your cart...</p>';

        fetchWithAuth(`${API_BASE_URL}/api/cart`)
            .then(cartData => {
                const { items, total } = cartData; // Now receiving total from backend
                if (items.length === 0) {
                    cartBody.innerHTML = '<p class="text-center text-muted">Your cart is empty.</p>';
                    cartFooter.style.display = 'none';
                    updateCartBadge(0); // Update badge with 0 items
                    return;
                }

                cartBody.innerHTML = '';
                items.forEach(item => {
                    cartBody.innerHTML += `
                        <div class="d-flex justify-content-between align-items-center mb-3 border-bottom pb-3">
                            <div class="d-flex align-items-center">
                                <img src="${item.artwork.image_url}" width="80" class="rounded me-3">
                                <div>
                                    <h6 class="mb-0">${item.artwork.title}</h6>
                                    <small class="text-muted">by ${item.artwork.artist.username}</small>
                                </div>
                            </div>
                            <div class="d-flex align-items-center">
                                <span class="fw-bold me-4">$${(item.artwork.price * item.quantity).toFixed(2)}</span>
                                <button class="btn btn-sm btn-outline-danger remove-from-cart-btn" data-item-id="${item.id}"><i class="fas fa-trash"></i></button>
                            </div>
                        </div>
                    `;
                });

                document.getElementById('cart-total').textContent = `$${total.toFixed(2)}`;
                cartFooter.style.display = 'block';
                updateCartBadge(items.length); // Update badge with the count of items
            })
            .catch((error) => {
                console.error("Error fetching cart:", error);
                // Only show error message inside the modal if it's open
                if (!updateBadgeOnly) cartBody.innerHTML = '<p class="text-danger">Could not load your cart.</p>';
            });
    }

    // Remove item from cart using event delegation
    document.getElementById('cart-body').addEventListener('click', function(event) {
        const removeCartBtn = event.target.closest('.remove-from-cart-btn');
        if (!removeCartBtn) return;

        const itemId = removeCartBtn.dataset.itemId;
        fetchWithAuth(`${API_BASE_URL}/api/cart/item/${itemId}`, { method: 'DELETE' })
            .then(() => {
                fetchCartItems(); // Refresh cart view
            })
            .catch(error => alert(`Error: ${error.message}`));
    });

    // Update cart badge count
    function updateCartBadge(count = null) {
        if (!currentUser) {
            document.getElementById('cart-badge').style.display = 'none';
            return;
        };
        // This function now only updates the UI based on a provided count.
        const badge = document.getElementById('cart-badge');
        badge.style.display = count > 0 ? 'block' : 'none';
        badge.textContent = count;
    }

    // Checkout
    document.getElementById('checkout-btn').addEventListener('click', async () => {
        if (!confirm('Are you sure you want to place this order?')) return;
        fetchWithAuth(`${API_BASE_URL}/api/cart/checkout`, { method: 'POST' })
            .then(data => {
                alert(data.message);
                fetchCartItems(); // Refresh cart (which will be empty)
                cartModal.hide(); 
            })
            .catch(error => alert(`Error: ${error.message}`));
    });

    // Handle search form submission
    const searchForm = document.getElementById('search-form');
    const searchInput = document.getElementById('search-input');
    if (searchForm) {
        searchForm.addEventListener('submit', (event) => {
            event.preventDefault();
            const searchTerm = searchInput.value.trim();
            fetchArtworks(searchTerm);
        });
    }

    // --- Upload Artwork Modal Enhancements ---
    const uploadImageInput = document.getElementById('uploadArtworkImage');
    const imagePreviewContainer = document.getElementById('imagePreviewContainer');
    const imagePreview = document.getElementById('imagePreview');

    if (uploadImageInput) {
        uploadImageInput.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                // Client-side validation for a better user experience
                const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
                if (!allowedTypes.includes(file.type)) {
                    alert('Invalid file type. Please select a JPG, PNG, or GIF image.');
                    this.value = ''; // Clear the input
                    return;
                }
                const maxSize = 5 * 1024 * 1024; // 5MB
                if (file.size > maxSize) {
                    alert('File is too large. Please select an image smaller than 5MB.');
                    this.value = ''; // Clear the input
                    return;
                }

                // Show image preview
                const reader = new FileReader();
                reader.onload = (e) => { imagePreview.src = e.target.result; };
                reader.readAsDataURL(file);
                imagePreviewContainer.style.display = 'block';
            }
        });
    }

    // Handle Upload Artwork Form Submission
    document.getElementById('uploadForm').addEventListener('submit', async (event) => {
        event.preventDefault();
        const form = event.target;
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;

        // Create FormData to handle file upload
        const formData = new FormData();
        formData.append('title', document.getElementById('uploadArtworkTitle').value);
        formData.append('description', document.getElementById('uploadArtworkDescription').value);
        formData.append('price', document.getElementById('uploadArtworkPrice').value);
        formData.append('category', document.getElementById('uploadArtworkCategory').value);
        formData.append('image', document.getElementById('uploadArtworkImage').files[0]);

        submitButton.disabled = true;
        submitButton.innerHTML = `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Uploading...`;

        try {
            // Note: When using FormData with fetch, you don't set the 'Content-Type' header.
            // The browser does it automatically with the correct boundary.
            const data = await fetchWithAuth(`${API_BASE_URL}/api/artworks`, {
                method: 'POST',
                body: formData,
            });
            showAuthMessage('uploadForm', data.message, false);
            setTimeout(() => {
                form.reset();
                uploadArtworkModal.hide();
                imagePreviewContainer.style.display = 'none'; // Hide preview on close
                imagePreview.src = '';
                fetchMyArtworks(); // Refresh the artist's artwork list
                showAuthMessage('uploadForm', '', false); // Clear message after modal hides
            }, 1500); // Give user time to see success message
        } catch (error) {
            showAuthMessage('uploadForm', error.message, true);
        } finally {
            submitButton.disabled = false;
            submitButton.innerHTML = originalButtonText;
        }
    });

    // Handle Edit Artwork Form Submission
    document.getElementById('editForm').addEventListener('submit', async (event) => {
        event.preventDefault();
        const artworkId = document.getElementById('editArtworkId').value;
        const updatedData = {
            title: document.getElementById('editArtworkTitle').value,
            description: document.getElementById('editArtworkDescription').value,
            price: document.getElementById('editArtworkPrice').value,
            category: document.getElementById('editArtworkCategory').value,
        };

        try {
            const data = await fetchWithAuth(`${API_BASE_URL}/api/artworks/${artworkId}`, {
                method: 'PUT',
                body: JSON.stringify(updatedData),
            });
            showProfileMessage('editForm', data.message, false); // Use profile message for edit form
            editArtworkModal.hide();
            fetchMyArtworks(); // Refresh the list to show changes
        } catch (error) {
            alert(`Error: ${error.message}`);
        }
    });

    // Event listener for the "Load More" button
    document.getElementById('loadMoreBtn').addEventListener('click', () => {
        // This is a placeholder. For this to work, the backend API at /api/artworks
        // would need to support pagination (e.g., accepting a `?page=2` query parameter).
        alert('Load More functionality requires backend pagination to be implemented.');
    });

    // When the profile link is clicked, fetch the latest data
    if (profileNavLink) {
        profileNavLink.addEventListener('click', fetchProfileData);
    }

    // --- Review Form Logic ---
    const starRatingContainer = document.querySelector('.star-rating');
    let selectedRating = 0;

    if (starRatingContainer) {
        starRatingContainer.addEventListener('click', e => {
            if (e.target.matches('i')) {
                selectedRating = parseInt(e.target.dataset.value);
                const stars = starRatingContainer.querySelectorAll('i');
                stars.forEach(star => {
                    if (parseInt(star.dataset.value) <= selectedRating) {
                        star.classList.remove('far');
                        star.classList.add('fas', 'text-warning');
                    } else {
                        star.classList.remove('fas', 'text-warning');
                        star.classList.add('far');
                    }
                });
            }
        });
    }

    // Handle review form submission
    const reviewForm = document.getElementById('review-form');
    if (reviewForm) {
        reviewForm.addEventListener('submit', e => {
            e.preventDefault();
            const artworkId = document.getElementById('reviewArtworkId').value;
            const comment = document.getElementById('review-comment').value;

            const reviewData = {
                rating: selectedRating,
                comment: comment
            };

            fetchWithAuth(`${API_BASE_URL}/api/artworks/${artworkId}/reviews`, {
                method: 'POST',
                body: JSON.stringify(reviewData)
            })
            .then(data => {
                alert(data.message || "Review submitted successfully!");
                // Reset form and refresh reviews
                reviewForm.reset();
                selectedRating = 0;
                starRatingContainer.querySelectorAll('i').forEach(star => {
                    star.classList.remove('fas', 'text-warning');
                    star.classList.add('far');
                });
                fetchAndRenderReviews(artworkId);
            })
            .catch(error => {
                console.error('Error submitting review:', error);
                alert(`Error: ${error.message}`);
            });
        });
    }

    // When modals are hidden, update the UI state
    document.getElementById('loginRegisterModal').addEventListener('hidden.bs.modal', () => {
        // Clear any lingering auth messages when the modal is closed manually
        const messageEl = document.querySelector('#loginRegisterModal .auth-message');
        if (messageEl) messageEl.textContent = '';
    });
    document.getElementById('cartModal').addEventListener('hidden.bs.modal', () => {
        // No action needed here, badge is updated on data change.
    });

    // Initial fetch of artworks when the page loads
    fetchArtworks();

    // --- SPA Routing: Handle hash changes for section visibility ---
    const routableSections = [
        'home', 'gallery', 'my-artworks', 'order-history', 'sales-dashboard', // 'my-artworks' is for the SPA section
        'reset-password', 'profile', 'about'
    ];

    function showSection(sectionId) {
        // Hide all routable sections first
        routableSections.forEach(id => {
            const section = document.getElementById(id);
            if (section) {
                section.style.display = 'none';
            }
        });

        // Show the requested section(s)
        if (sectionId === 'home' || sectionId === 'gallery' || !sectionId) {
            // Default view: home and gallery
            document.getElementById('home').style.display = 'block';
            document.getElementById('gallery').style.display = 'block';
            fetchArtworks(); // Always refresh main gallery when navigating to home/gallery
        } else {
            const targetSection = document.getElementById(sectionId);
            if (targetSection) {
                targetSection.style.display = 'block';
                targetSection.scrollIntoView({ behavior: 'smooth' });
            }
        }
    }

    function handleHashChange() {
        const hash = window.location.hash.substring(1); // Remove the '#'
        const urlParams = new URLSearchParams(window.location.search);
        const resetToken = urlParams.get('reset_token');

        // Handle password reset flow specifically
        if (resetToken && hash === 'reset-password') {
            showSection('reset-password');
            document.getElementById('resetTokenInput').value = resetToken;
            // Optionally hide nav if you want a full-page reset experience
            // document.querySelector('nav').style.display = 'none';
            return; // Exit early if handling reset flow
        }

        // General section routing
        showSection(hash);

        // Fetch data specific to the section if user is logged in
        if (currentUser) {
            if (hash === 'profile') fetchProfileData();
            else if (hash === 'my-artworks' && currentUser.role === 'artist') fetchMyArtworks();
            else if (hash === 'order-history' && currentUser.role === 'buyer') fetchOrderHistory();
            else if (hash === 'sales-dashboard' && currentUser.role === 'artist') fetchSalesDashboard();
            fetchCartItems(true); // Always get the latest cart badge count when navigating
        }
    }

    window.addEventListener('hashchange', handleHashChange);

    // --- Centralized Navigation and Logout Listeners ---
    if (logoutNavLink) {
        logoutNavLink.addEventListener('click', (event) => {
            event.preventDefault();
            if (confirm('Are you sure you want to log out?')) {
                // The handleLogout function now makes an API call, so we call it directly.
                handleLogout(); 
            }
        });
    }

    // Fetch cart items only when the cart modal is about to be shown
    document.getElementById('cartModal').addEventListener('show.bs.modal', () => {
        fetchCartItems();
    });

    // --- Application Start ---    
    initializeSession(); // Set the initial state of the application
});