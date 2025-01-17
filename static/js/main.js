document.addEventListener('DOMContentLoaded', function() {
    // Form elements
    const form = document.getElementById('fraudDetectionForm');
    const loading = document.querySelector('.loading');
    const result = document.getElementById('result');
    const transactionDateInput = document.querySelector('input[name="transactionDate"]');

    // Transaction ID validation
    document.querySelector('input[name="transaction_id"]').addEventListener('input', function(e) {
        this.value = this.value.replace(/[^A-Za-z0-9]/g, '');
    });

    // User ID validation
    document.querySelector('input[name="user_id"]').addEventListener('input', function(e) {
        this.value = this.value.replace(/[^A-Za-z0-9]/g, '');
    });

    // Amount validation
    document.querySelector('input[name="amount"]').addEventListener('input', function(e) {
        if (this.value < 0) {
            this.value = '';
            alert('Amount cannot be negative');
        }
    });

    // Transaction date validation
    transactionDateInput.addEventListener('change', function(e) {
        const selectedDate = new Date(this.value);
        const now = new Date();
        
        if (selectedDate > now) {
            alert('Transaction date cannot be in the future');
            this.value = '';
        }
    });

    // Form submission
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const submitButton = this.querySelector('button');
        loading.style.display = 'block';
        result.style.display = 'none';
        submitButton.disabled = true;
        
        try {
            const formData = new FormData(this);
            const response = await fetch('/predict', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            result.style.display = 'block';
            result.className = data.probability > 0.5 ? 'high-risk' : 'low-risk';
            
            const fraudIndicatorsList = data.fraud_indicators && data.fraud_indicators.length > 0 
                ? `<div class="fraud-indicators">
                    <ul>
                        ${data.fraud_indicators.map(indicator => `<li>${indicator}</li>`).join('')}
                    </ul>
                   </div>`
                : '';
            
            result.innerHTML = `
                <h3>Analysis Result</h3>
                <p><strong>Transaction ID:</strong> ${formData.get('transaction_id')}</p>
                <p><strong>User ID:</strong> ${formData.get('user_id')}</p>
                <p><strong>Transaction Date:</strong> ${formData.get('transactionDate')}</p>
                <p><strong>Risk Level:</strong> ${data.risk_level}</p>
                <p><strong>Fraud Probability:</strong> ${(data.probability * 100).toFixed(2)}%</p>
                <p><strong>Message:</strong> ${data.message}</p>
                ${fraudIndicatorsList}
                <p><strong>Timestamp:</strong> ${data.timestamp}</p>
            `;
        } catch (error) {
            console.error('Error:', error);
            result.style.display = 'block';
            result.className = 'high-risk';
            result.innerHTML = `
                <h3>Error</h3>
                <p>${error.message || 'An error occurred while processing your request. Please try again.'}</p>
            `;
        } finally {
            loading.style.display = 'none';
            submitButton.disabled = false;
        }
    });
});