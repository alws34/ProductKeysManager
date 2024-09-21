document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('search-btn').addEventListener('click', function() {
        let query = document.getElementById('search').value;

        // Perform a search request using fetch
        fetch(`/search?query=${query}`)
            .then(response => response.json())
            .then(data => {
                let resultDiv = document.getElementById('results');
                resultDiv.innerHTML = ''; // Clear previous results
                if (data.keys.length > 0) {
                    data.keys.forEach(key => {
                        let keyElement = document.createElement('div');
                        keyElement.textContent = key.serial_key + (key.is_in_use ? ' (In Use)' : ' (Available)');
                        resultDiv.appendChild(keyElement);
                    });
                } else {
                    resultDiv.innerHTML = '<p>No keys found.</p>';
                }
            })
            .catch(error => {
                console.error('Error fetching keys:', error);
            });
    });
});
