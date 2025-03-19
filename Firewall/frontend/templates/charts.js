// File: charts.js

// Traffic Distribution Pie Chart
const trafficCtx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(trafficCtx, {
    type: 'pie',
    data: {
        labels: ['HTTP', 'HTTPS', 'FTP', 'Other'],
        datasets: [{
            label: 'Traffic Distribution',
            data: [40, 35, 15, 10], // Example data
            backgroundColor: [
                'rgba(255, 99, 132, 0.2)',
                'rgba(54, 162, 235, 0.2)',
                'rgba(255, 206, 86, 0.2)',
                'rgba(75, 192, 192, 0.2)'
            ],
            borderColor: [
                'rgba(255, 99, 132, 1)',
                'rgba(54, 162, 235, 1)',
                'rgba(255, 206, 86, 1)',
                'rgba(75, 192, 192, 1)'
            ],
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: {
                position: 'top',
            },
            title: {
                display: true,
                text: 'Traffic Distribution by Protocol'
            }
        }
    }
});

// Real-Time Traffic Line Graph
const realTimeCtx = document.getElementById('realTimeChart').getContext('2d');
const realTimeChart = new Chart(realTimeCtx, {
    type: 'line',
    data: {
        labels: [], // Time stamps
        datasets: [{
            label: 'Active Users',
            data: [ ], // Real-time data
            fill: false,
            borderColor: 'rgb(75, 192, 192)',
            tension: 0.1
        }]
    },
    options: {
        responsive: true,
        scales: {
            x: {
                type: 'time',
                time: {
                    unit: 'second'
                },
                title: {
                    display: true,
                    text: 'Time'
                }
            },
            y: {
                title: {
                    display: true,
                    text: 'Active Users'
                },
                min: 0,
                max: 100
            }
        },
        plugins: {
            legend: {
                display: true,
                position: 'top',
            }
        }
    }
});

// Simulate real-time data updates
setInterval(() => {
    const now = new Date();
    const randomUsers = Math.floor(Math.random() * 100);
    
    realTimeChart.data.labels.push(now);
    realTimeChart.data.datasets[0].data.push(randomUsers);
    
    if (realTimeChart.data.labels.length > 20) {
        realTimeChart.data.labels.shift();
        realTimeChart.data.datasets[0].data.shift();
    }
    
    realTimeChart.update();
}, 1000);
