document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('checkSafety').addEventListener('click', function() {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            var url = tabs[0].url;
            console.log('URL:', url);

            // Show loading indicator
            document.getElementById('buttonText').style.display = 'none';
            document.getElementById('loading').style.display = 'inline';

            // Send POST request to Flask API
            fetch('http://127.0.0.1:5000/predict', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ url: url })
                })
                .then(response => response.json())
                .then(data => {
                    console.log('Prediction:', data.prediction);

                    // Hide loading indicator
                    document.getElementById('loading').style.display = 'none';
                    document.getElementById('buttonText').style.display = 'inline';

                    // Display prediction result
                    var predictionResult = document.getElementById('predictionResult');
                    predictionResult.innerText = 'Prediction: ' + data.prediction;
                    if (data.prediction === 'suspicious') {
                        predictionResult.className = 'suspicious';
                        document.getElementById('container').style.backgroundColor = '#FFCCCC'; // Light red
                    } else {
                        predictionResult.className = 'safe';
                        document.getElementById('container').style.backgroundColor = '#C3E6CB'; // Light green
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    // Handle error
                });
        });
    });
});