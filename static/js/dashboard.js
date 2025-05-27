document.addEventListener('DOMContentLoaded', function() {
    fetchCalendarEvents();
    fetchEmailSummary();
    checkOpenAIApiKeyStatus();
    setupApiKeySaveButtons();
    startEmailPolling();
    startEventPolling(); 
    fetchRecentActivities(); // Fetch initial recent activities
});

let emailPollingIntervalId = null;
const EMAIL_POLLING_INTERVAL = 30000; // 30 seconds for email
let eventPollingIntervalId = null;
const EVENT_POLLING_INTERVAL = 60000; // 1 minute for calendar events

function fetchRecentActivities() {
    const activitiesContainer = document.getElementById('recent-activities-container');
    if (!activitiesContainer) return;

    activitiesContainer.innerHTML = '<p class="loading-message">Loading activities...</p>';

    fetch('/api/dashboard/recent_activities')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            activitiesContainer.innerHTML = ''; // Clear loading message
            if (data.error) {
                throw new Error(data.error);
            }
            if (data.activities && data.activities.length > 0) {
                const ul = document.createElement('ul');
                data.activities.forEach(activity => {
                    const li = document.createElement('li');
                    li.innerHTML = `
                        <span class="activity-timestamp">${activity.timestamp}</span>
                        <span class="activity-type">${activity.activity_type}:</span>
                        <span class="activity-description">${activity.description}</span>
                    `;
                    ul.appendChild(li);
                });
                activitiesContainer.appendChild(ul);
            } else {
                activitiesContainer.innerHTML = '<p class="empty-message">No recent activities to display.</p>';
            }
        })
        .catch(error => {
            console.error('Error fetching recent activities:', error);
            activitiesContainer.innerHTML = `<p class="error-message">Could not load recent activities: ${error.message}</p>`;
        });
}

function startEmailPolling() {
    if (emailPollingIntervalId) {
        clearInterval(emailPollingIntervalId); 
    }
    checkNewEmail(); 
    emailPollingIntervalId = setInterval(checkNewEmail, EMAIL_POLLING_INTERVAL);
    console.log("Email polling started.");
}

function startEventPolling() {
    if (eventPollingIntervalId) {
        clearInterval(eventPollingIntervalId);
    }
    checkUpcomingCalendarEvent(); 
    eventPollingIntervalId = setInterval(checkUpcomingCalendarEvent, EVENT_POLLING_INTERVAL);
    console.log("Calendar event polling started.");
}

function stopEventPolling() {
    if (eventPollingIntervalId) {
        clearInterval(eventPollingIntervalId);
        eventPollingIntervalId = null;
        console.log("Calendar event polling stopped.");
    }
}

function checkUpcomingCalendarEvent() {
    console.log("Checking for upcoming calendar events...");
    fetch('/api/calendar/check_upcoming_event')
        .then(response => {
            if (!response.ok) {
                if (response.status === 401) {
                    console.error("Unauthorized to check calendar events. Stopping event polling.");
                    stopEventPolling();
                    throw new Error('Unauthorized. Please login again.');
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                console.error('Error checking upcoming calendar events:', data.error, data.details || '');
                 if (data.error.includes("Google API authorization error")) {
                    console.error("Google API authorization error for events. Stopping polling.");
                    stopEventPolling();
                }
                return;
            }

            if (data.upcoming_event_found) {
                console.log("Upcoming event found:", data);
                displayUpcomingEventPopup(data);
                fetchRecentActivities(); // Refresh activities
            } else if (data.message) {
                console.log(data.message); 
            }
        })
        .catch(error => {
            console.error('Failed to check upcoming calendar events:', error.message);
        });
}

function displayUpcomingEventPopup(eventData) {
    const popup = document.getElementById('upcoming-event-popup');
    if (!popup) {
        console.error("Upcoming event popup HTML element not found.");
        return;
    }

    document.getElementById('popup-event-title').textContent = eventData.title || 'N/A';
    document.getElementById('popup-event-start-time').textContent = new Date(eventData.start_time).toLocaleString() || 'N/A';
    document.getElementById('popup-event-end-time').textContent = new Date(eventData.end_time).toLocaleString() || 'N/A';

    const attendeesList = document.getElementById('popup-event-attendees');
    attendeesList.innerHTML = ''; 
    if (eventData.attendees && eventData.attendees.length > 0) {
        eventData.attendees.forEach(attendee => {
            const li = document.createElement('li');
            li.textContent = attendee;
            attendeesList.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.textContent = 'No attendees listed or you are the only one.';
        attendeesList.appendChild(li);
    }

    const joinButton = document.getElementById('popup-event-action-join');
    if (eventData.hangout_link) {
        joinButton.href = eventData.hangout_link;
        joinButton.style.display = 'inline-block';
        joinButton.textContent = "Join Meeting";
    } else if (eventData.html_link) { 
        joinButton.href = eventData.html_link;
        joinButton.style.display = 'inline-block';
        joinButton.textContent = "View Event"; 
    }
    else {
        joinButton.style.display = 'none';
    }
    
    const dismissButton = document.getElementById('popup-event-action-dismiss');
    const closeButton = document.getElementById('close-upcoming-event-popup');

    dismissButton.onclick = function() { popup.style.display = 'none'; };
    closeButton.onclick = function() { popup.style.display = 'none'; };

    popup.style.display = 'flex';
}

function stopEmailPolling() {
    if (emailPollingIntervalId) {
        clearInterval(emailPollingIntervalId);
        emailPollingIntervalId = null;
        console.log("Email polling stopped.");
    }
}

function checkNewEmail() {
    console.log("Checking for new email...");
    fetch('/api/gmail/check_new_email')
        .then(response => {
            if (!response.ok) {
                if (response.status === 401) { 
                    console.error("Unauthorized to check email. Stopping polling.");
                    stopEmailPolling(); 
                    throw new Error('Unauthorized. Please login again.');
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                console.error('Error checking new email:', data.error, data.details || '');
                if (data.error.includes("Google API authorization error")) {
                    console.error("Google API authorization error. Stopping polling.");
                    stopEmailPolling();
                }
                return; 
            }

            if (data.new_email) {
                console.log("New email received:", data);
                displayNewEmailPopup(data);
                fetchRecentActivities(); // Refresh activities
            } else if (data.message) {
                console.log(data.message); 
            }
        })
        .catch(error => {
            console.error('Failed to check new email:', error.message);
        });
}

function displayNewEmailPopup(emailData) {
    const popup = document.getElementById('new-mail-popup');
    if (!popup) {
        console.error("New mail popup HTML element not found.");
        return;
    }
    popup.dataset.emailData = JSON.stringify(emailData);

    document.getElementById('popup-email-from').textContent = emailData.from_header || 'N/A'; 
    document.getElementById('popup-email-subject').textContent = emailData.subject || 'N/A';
    document.getElementById('popup-email-summary').textContent = emailData.summary || 'No summary available.';

    const repliesContainer = document.getElementById('popup-suggested-replies');
    repliesContainer.innerHTML = ''; 
    
    const statusElement = document.createElement('p'); 
    statusElement.id = 'popup-reply-status';
    statusElement.style.marginTop = '10px';
    repliesContainer.appendChild(statusElement);

    if (emailData.suggested_replies && emailData.suggested_replies.length > 0) {
        emailData.suggested_replies.forEach(replyText => {
            if (replyText) { 
                const button = document.createElement('button');
                button.textContent = replyText;
                button.onclick = function() {
                    sendSuggestedReply(replyText);
                };
                repliesContainer.appendChild(button);
            }
        });
    } else {
        repliesContainer.innerHTML = '<p>No suggested replies available.</p>';
    }
    
    const closeButton = document.getElementById('close-new-mail-popup');
    if (closeButton) {
        closeButton.onclick = function() {
            popup.style.display = 'none';
        };
    }

    const archiveButton = document.getElementById('popup-action-archive');
    if (archiveButton) {
        archiveButton.onclick = function() {
            const currentEmailData = JSON.parse(popup.dataset.emailData);
            console.log("Archive action clicked for email ID:", currentEmailData.id);
            alert("Archive functionality not yet implemented.");
            popup.style.display = 'none';
        };
    }

    const replyInGmailButton = document.getElementById('popup-action-reply');
    if (replyInGmailButton) {
        replyInGmailButton.onclick = function() {
            const currentEmailData = JSON.parse(popup.dataset.emailData);
            console.log("Reply in Gmail action clicked for email ID:", currentEmailData.id);
            const gmailLink = `https://mail.google.com/mail/u/0/#inbox/${currentEmailData.id}`;
            window.open(gmailLink, '_blank');
            popup.style.display = 'none';
        };
    }
    popup.style.display = 'flex'; 
}

function sendSuggestedReply(replyBody) {
    const popup = document.getElementById('new-mail-popup');
    const emailData = JSON.parse(popup.dataset.emailData);
    const statusElement = document.getElementById('popup-reply-status');

    if (!emailData || !emailData.from_email || !emailData.subject || !emailData.thread_id || !emailData.id) {
        console.error("Missing necessary data to send reply.", emailData);
        if(statusElement) statusElement.textContent = "Error: Missing email data to send reply.";
        if(statusElement) statusElement.className = 'error';
        return;
    }
    
    statusElement.textContent = 'Sending reply...';
    statusElement.className = '';

    const payload = {
        to: emailData.from_email, 
        subject: emailData.subject, 
        body: replyBody,
        thread_id: emailData.thread_id,
        message_id: emailData.id 
    };

    fetch('/api/gmail/send_reply', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    })
    .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
    .then(result => {
        if (!result.ok) {
            throw new Error(result.data.error || `Failed to send reply. Status: ${result.status}`);
        }
        statusElement.textContent = result.data.message || 'Reply sent successfully!';
        statusElement.className = 'success';
        fetchRecentActivities(); // Refresh activities after sending reply
        
        setTimeout(() => {
            popup.style.display = 'none';
        }, 2000); 
    })
    .catch(error => {
        console.error('Error sending reply:', error);
        statusElement.textContent = `Error: ${error.message}`;
        statusElement.className = 'error';
    });
}

function setupApiKeySaveButtons() {
    const saveButton = document.getElementById('save-openai-api-key-btn');
    const updateButton = document.getElementById('update-openai-api-key-btn');

    if (saveButton) {
        saveButton.addEventListener('click', function() {
            saveOpenAIApiKey('openai-api-key-input', 'openai-api-key-status');
        });
    }
    if (updateButton) {
        updateButton.addEventListener('click', function() {
            saveOpenAIApiKey('openai-api-key-input-update', 'openai-api-key-status-update');
        });
    }
}

function checkOpenAIApiKeyStatus() {
    const formContainer = document.getElementById('openai-api-key-form-container');
    const setContainer = document.getElementById('openai-api-key-set-message');
    const statusElement = document.getElementById('openai-api-key-status'); 

    fetch('/api/openai/apikey/status')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                 throw new Error(data.error + (data.details ? ` Details: ${data.details}` : ''));
            }
            if (data.is_set) {
                formContainer.style.display = 'none';
                setContainer.style.display = 'block';
            } else {
                formContainer.style.display = 'block';
                setContainer.style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error checking OpenAI API key status:', error);
            if (statusElement) statusElement.textContent = `Error checking API key status: ${error.message}`;
            formContainer.style.display = 'block'; 
            setContainer.style.display = 'none';
        });
}

function saveOpenAIApiKey(inputId, statusElementId) {
    const apiKeyInput = document.getElementById(inputId);
    const statusElement = document.getElementById(statusElementId);

    if (!apiKeyInput || !apiKeyInput.value.trim()) {
        if (statusElement) statusElement.textContent = 'API Key cannot be empty.';
        if (statusElement) statusElement.className = 'error';
        return;
    }

    statusElement.textContent = 'Saving...';
    statusElement.className = '';

    fetch('/api/openai/apikey', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ api_key: apiKeyInput.value.trim() }),
    })
    .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
    .then(result => {
        if (!result.ok) {
            throw new Error(result.data.error || `Failed to save API key. Status: ${result.status}`);
        }
        statusElement.textContent = result.data.message || 'API Key saved successfully!';
        statusElement.className = 'success'; 
        apiKeyInput.value = ''; 
        
        checkOpenAIApiKeyStatus(); 
        fetchRecentActivities(); // Refresh activities after potential key save
    })
    .catch(error => {
        console.error('Error saving OpenAI API key:', error);
        statusElement.textContent = `Error: ${error.message}`;
        statusElement.className = 'error';
    });
}

function fetchCalendarEvents() {
    const eventsContainer = document.getElementById('calendar-events-container');
    eventsContainer.innerHTML = '<p class="loading-message">Loading calendar events...</p>'; 

    fetch('/api/calendar/events')
        .then(response => {
            if (!response.ok) {
                if (response.status === 401) {
                    throw new Error('Unauthorized. Please login again.');
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            eventsContainer.innerHTML = ''; 
            if (data.error) {
                const errorMessage = data.details ? `${data.error} Details: ${data.details}` : data.error;
                throw new Error(errorMessage);
            }
            if (data.events && data.events.length > 0) {
                const ul = document.createElement('ul');
                data.events.forEach(event => {
                    const li = document.createElement('li');
                    const startTime = new Date(event.start).toLocaleString();
                    const endTime = new Date(event.end).toLocaleString();
                    
                    let eventHtml = `<strong>${event.summary}</strong><br>
                                     <small>Start: ${startTime}</small><br>
                                     <small>End: ${endTime}</small>`;
                    if (event.link) {
                        eventHtml += `<br><a href="${event.link}" target="_blank">View Event</a>`;
                    }
                    li.innerHTML = eventHtml;
                    ul.appendChild(li);
                });
                eventsContainer.appendChild(ul);
            } else {
                eventsContainer.innerHTML = '<p class="empty-message">No upcoming calendar events found.</p>';
            }
        })
        .catch(error => {
            console.error('Error fetching calendar events:', error);
            eventsContainer.innerHTML = `<p class="error-message">Could not load calendar events: ${error.message}</p>`;
            if (error.message.includes('Unauthorized')) {
                eventsContainer.innerHTML += '<p><a href="/login/google">Login with Google</a></p>';
            }
        });
}

function fetchEmailSummary() {
    const emailContainer = document.getElementById('email-summary-container');
    emailContainer.innerHTML = '<p class="loading-message">Loading email summary...</p>';

    fetch('/api/gmail/emails')
        .then(response => {
            if (!response.ok) {
                if (response.status === 401) {
                    throw new Error('Unauthorized. Please login again to view emails.');
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            emailContainer.innerHTML = ''; 
            if (data.error) {
                const errorMessage = data.details ? `${data.error} Details: ${data.details}` : data.error;
                throw new Error(errorMessage);
            }
            if (data.emails && data.emails.length > 0) {
                const ul = document.createElement('ul');
                data.emails.forEach(email => {
                    const li = document.createElement('li');
                    const emailDate = new Date(email.date).toLocaleString();
                    
                    let emailHtml = `<strong>${email.subject || 'No Subject'}</strong><br>
                                     <small>From: ${email.from || 'Unknown Sender'}</small><br>
                                     <small>Date: ${emailDate}</small><br>
                                     <p class="snippet">${email.snippet || 'No snippet available.'}</p>`;
                    li.innerHTML = emailHtml;
                    ul.appendChild(li);
                });
                emailContainer.appendChild(ul);
            } else if (data.message) { 
                 emailContainer.innerHTML = `<p class="empty-message">${data.message}</p>`;
            }
            else {
                emailContainer.innerHTML = '<p class="empty-message">No recent emails found.</p>';
            }
        })
        .catch(error => {
            console.error('Error fetching email summary:', error);
            emailContainer.innerHTML = `<p class="error-message">Could not load email summary: ${error.message}</p>`;
            if (error.message.includes('Unauthorized')) {
                emailContainer.innerHTML += '<p><a href="/login/google">Login with Google</a></p>';
            }
        });
}
