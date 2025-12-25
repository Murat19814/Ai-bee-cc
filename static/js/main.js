/**
 * AI BEE CC - Main JavaScript
 * Call Center Platform
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize components
    initSidebar();
    initNavGroups();
    initSocket();
    initNotifications();
    initAgentStatus();
});

/**
 * Sidebar Toggle & Control
 */
function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebarClose = document.getElementById('sidebarClose');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    
    if (!sidebar) return;
    
    // Open sidebar
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.add('open');
            if (sidebarOverlay) {
                sidebarOverlay.classList.add('active');
            }
            document.body.style.overflow = 'hidden';
        });
    }
    
    // Close sidebar
    function closeSidebar() {
        sidebar.classList.remove('open');
        if (sidebarOverlay) {
            sidebarOverlay.classList.remove('active');
        }
        document.body.style.overflow = '';
    }
    
    if (sidebarClose) {
        sidebarClose.addEventListener('click', closeSidebar);
    }
    
    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', closeSidebar);
    }
    
    // Close on escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && sidebar.classList.contains('open')) {
            closeSidebar();
        }
    });
}

/**
 * Collapsible Navigation Groups
 */
function initNavGroups() {
    const navGroups = document.querySelectorAll('.nav-group');
    
    navGroups.forEach(function(group) {
        const toggle = group.querySelector('.nav-group-toggle');
        const menu = group.querySelector('.nav-group-menu');
        
        if (!toggle || !menu) return;
        
        // Check if any subitem is active
        const hasActiveItem = menu.querySelector('.nav-subitem.active');
        if (hasActiveItem) {
            group.classList.add('open');
        }
        
        toggle.addEventListener('click', function() {
            // Close other groups (accordion behavior - optional)
            // navGroups.forEach(g => {
            //     if (g !== group) g.classList.remove('open');
            // });
            
            group.classList.toggle('open');
        });
    });
    
    // Set active state for current page
    const currentPath = window.location.pathname;
    const navItems = document.querySelectorAll('.nav-item, .nav-subitem');
    
    navItems.forEach(function(item) {
        const href = item.getAttribute('href');
        if (href && currentPath === href) {
            item.classList.add('active');
            
            // If it's a subitem, open parent group
            const parentGroup = item.closest('.nav-group');
            if (parentGroup) {
                parentGroup.classList.add('open');
            }
        }
    });
}

/**
 * Socket.IO Connection
 */
function initSocket() {
    if (typeof io === 'undefined') return;
    
    try {
        const socket = io({
            transports: ['websocket', 'polling']
        });
        
        socket.on('connect', function() {
            console.log('🐝 AI BEE CC - Connected to server');
        });
        
        socket.on('disconnect', function() {
            console.log('⚠️ Disconnected from server');
        });
        
        // Call events
        socket.on('incoming_call', function(data) {
            showIncomingCallPopup(data);
        });
        
        socket.on('call_ended', function(data) {
            hideCallPopup();
        });
        
        // Queue updates
        socket.on('queue_update', function(data) {
            updateQueueStats(data);
        });
        
        // Agent status updates
        socket.on('agent_status_update', function(data) {
            updateAgentStatus(data);
        });
        
        // Store socket globally
        window.appSocket = socket;
    } catch (e) {
        console.error('Socket connection failed:', e);
    }
}

/**
 * Notifications
 */
function initNotifications() {
    const notificationBtn = document.querySelector('.notification-btn');
    
    if (notificationBtn) {
        notificationBtn.addEventListener('click', function() {
            // Toggle notification dropdown
            console.log('Notifications clicked');
        });
    }
}

/**
 * Agent Status Handler
 */
function initAgentStatus() {
    const statusSelect = document.getElementById('agentStatus');
    
    if (statusSelect) {
        statusSelect.addEventListener('change', function() {
            const newStatus = this.value;
            updateMyStatus(newStatus);
        });
    }
}

function updateMyStatus(status) {
    fetch('/api/agent/status', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: status })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Durum güncellendi', 'success');
        } else {
            showToast('Durum güncellenemedi', 'danger');
        }
    })
    .catch(error => {
        console.error('Status update failed:', error);
        showToast('Bağlantı hatası', 'danger');
    });
}

/**
 * Incoming Call Popup
 */
function showIncomingCallPopup(data) {
    // Remove existing popup
    hideCallPopup();
    
    const popup = document.createElement('div');
    popup.className = 'customer-popup';
    popup.id = 'callPopup';
    popup.innerHTML = `
        <div class="popup-header">
            <span class="popup-title">
                <i class="ti ti-phone-incoming"></i>
                Gelen Çağrı
            </span>
            <button class="popup-close" onclick="hideCallPopup()">
                <i class="ti ti-x"></i>
            </button>
        </div>
        <div class="popup-content">
            <div class="caller-info">
                <div class="caller-number">${data.phone || 'Bilinmiyor'}</div>
                <div class="caller-name">${data.name || 'Yeni Arayan'}</div>
            </div>
            ${data.customer_id ? `
                <div class="customer-quick-info">
                    <div><strong>Müşteri:</strong> ${data.customer_name}</div>
                    <div><strong>Son Çağrı:</strong> ${data.last_call || 'İlk çağrı'}</div>
                </div>
            ` : ''}
        </div>
        <div class="popup-actions">
            <button class="btn btn-success" onclick="answerCall('${data.call_id}')">
                <i class="ti ti-phone"></i>
                Cevapla
            </button>
            <button class="btn btn-danger" onclick="rejectCall('${data.call_id}')">
                <i class="ti ti-phone-off"></i>
                Reddet
            </button>
        </div>
    `;
    
    document.body.appendChild(popup);
    
    // Play ring tone
    playRingTone();
}

function hideCallPopup() {
    const popup = document.getElementById('callPopup');
    if (popup) {
        popup.remove();
    }
    stopRingTone();
}

function answerCall(callId) {
    if (window.appSocket) {
        window.appSocket.emit('answer_call', { call_id: callId });
    }
    hideCallPopup();
}

function rejectCall(callId) {
    if (window.appSocket) {
        window.appSocket.emit('reject_call', { call_id: callId });
    }
    hideCallPopup();
}

/**
 * Ring Tone
 */
let ringAudio = null;

function playRingTone() {
    // Simple beep using Web Audio API
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.value = 440;
        oscillator.type = 'sine';
        gainNode.gain.value = 0.1;
        
        oscillator.start();
        
        ringAudio = {
            oscillator: oscillator,
            context: audioContext
        };
        
        // Beep pattern
        let beeping = true;
        const beepInterval = setInterval(() => {
            if (!ringAudio) {
                clearInterval(beepInterval);
                return;
            }
            beeping = !beeping;
            gainNode.gain.value = beeping ? 0.1 : 0;
        }, 500);
    } catch (e) {
        console.log('Audio not available');
    }
}

function stopRingTone() {
    if (ringAudio) {
        try {
            ringAudio.oscillator.stop();
            ringAudio.context.close();
        } catch (e) {}
        ringAudio = null;
    }
}

/**
 * Queue Stats Update
 */
function updateQueueStats(data) {
    const queueElements = document.querySelectorAll('[data-queue-id]');
    
    queueElements.forEach(el => {
        const queueId = el.dataset.queueId;
        if (data[queueId]) {
            const waiting = el.querySelector('.queue-waiting');
            const agents = el.querySelector('.queue-agents');
            
            if (waiting) waiting.textContent = data[queueId].waiting;
            if (agents) agents.textContent = data[queueId].agents;
        }
    });
}

/**
 * Agent Status Update
 */
function updateAgentStatus(data) {
    const agentRows = document.querySelectorAll('[data-agent-id]');
    
    agentRows.forEach(row => {
        const agentId = row.dataset.agentId;
        if (data.agent_id === agentId) {
            const statusBadge = row.querySelector('.agent-status');
            if (statusBadge) {
                statusBadge.className = 'badge badge-' + getStatusColor(data.status);
                statusBadge.textContent = getStatusText(data.status);
            }
        }
    });
}

function getStatusColor(status) {
    const colors = {
        'available': 'success',
        'busy': 'danger',
        'break': 'warning',
        'training': 'info',
        'after_call_work': 'warning',
        'offline': 'secondary'
    };
    return colors[status] || 'secondary';
}

function getStatusText(status) {
    const texts = {
        'available': 'Müsait',
        'busy': 'Meşgul',
        'break': 'Mola',
        'training': 'Eğitim',
        'after_call_work': 'ACW',
        'offline': 'Çevrimdışı'
    };
    return texts[status] || status;
}

/**
 * Toast Notification
 */
function showToast(message, type = 'info') {
    const existingToast = document.querySelector('.toast');
    if (existingToast) existingToast.remove();
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <i class="ti ti-${type === 'success' ? 'check' : type === 'danger' ? 'x' : 'info-circle'}"></i>
        <span>${message}</span>
    `;
    
    toast.style.cssText = `
        position: fixed;
        bottom: 1.5rem;
        right: 1.5rem;
        padding: 1rem 1.5rem;
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: var(--border-radius);
        color: var(--${type === 'success' ? 'success' : type === 'danger' ? 'danger' : 'info'});
        display: flex;
        align-items: center;
        gap: 0.75rem;
        box-shadow: var(--shadow-lg);
        z-index: 9999;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

/**
 * Click to Call
 */
function clickToCall(phone) {
    if (window.appSocket) {
        window.appSocket.emit('initiate_call', { phone: phone });
        showToast('Çağrı başlatılıyor...', 'info');
    }
}

/**
 * Confirm Dialog
 */
function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}

/**
 * Format Phone Number
 */
function formatPhone(phone) {
    if (!phone) return '';
    const cleaned = phone.replace(/\D/g, '');
    if (cleaned.length === 10) {
        return `(${cleaned.slice(0,3)}) ${cleaned.slice(3,6)} ${cleaned.slice(6)}`;
    }
    return phone;
}

/**
 * Format Duration
 */
function formatDuration(seconds) {
    if (!seconds) return '00:00';
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

/**
 * Copy to Clipboard
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Kopyalandı!', 'success');
    }).catch(() => {
        showToast('Kopyalanamadı', 'danger');
    });
}

// Add CSS animation keyframes
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOut {
        from {
            opacity: 1;
            transform: translateY(0);
        }
        to {
            opacity: 0;
            transform: translateY(10px);
        }
    }
    
    .customer-popup {
        position: fixed;
        bottom: 1.5rem;
        right: 1.5rem;
        width: 360px;
        background: var(--bg-card);
        border: 1px solid var(--border-gold);
        border-radius: var(--border-radius-lg);
        box-shadow: var(--shadow-lg), 0 0 30px rgba(245, 166, 35, 0.2);
        z-index: 1000;
        animation: slideIn 0.3s ease;
    }
    
    .popup-header {
        padding: 1rem;
        background: var(--primary-gradient);
        border-radius: var(--border-radius-lg) var(--border-radius-lg) 0 0;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    
    .popup-title {
        font-family: var(--font-display);
        font-weight: 700;
        color: var(--text-dark);
        letter-spacing: 0.05em;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .popup-close {
        background: none;
        border: none;
        color: var(--text-dark);
        font-size: 1.5rem;
        cursor: pointer;
        opacity: 0.8;
    }
    
    .popup-close:hover {
        opacity: 1;
    }
    
    .popup-content {
        padding: 1.25rem;
    }
    
    .caller-info {
        text-align: center;
        margin-bottom: 1rem;
    }
    
    .caller-number {
        font-family: var(--font-mono);
        font-size: 1.25rem;
        font-weight: 600;
        color: var(--primary);
    }
    
    .caller-name {
        font-size: 0.875rem;
        color: var(--text-muted);
        margin-top: 0.25rem;
    }
    
    .popup-actions {
        display: flex;
        gap: 0.75rem;
        padding: 1rem;
        border-top: 1px solid var(--border-color);
    }
    
    .popup-actions .btn {
        flex: 1;
    }
`;
document.head.appendChild(style);
