chrome.contextMenus.create({
    id: "checkWebsite",
    title: "Check Website Safety",
    contexts: ["page"]
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "checkWebsite") {
        fetch('http://127.0.0.1:5000/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: tab.url })
            })
            .then(response => response.json())
            .then(data => {
                console.log(data);
                // Handle API response
            })
            .catch(error => {
                console.error('Error:', error);
            });
    }
});