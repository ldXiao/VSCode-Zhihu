const axios = require('axios');

async function testZhihuQRCodeAPI() {
    try {
        console.log('Testing Zhihu QR Code API...');
        
        const axiosInstance = axios.create({
            timeout: 10000,
            withCredentials: true
        });
        
        // First, get session cookies
        console.log('Step 1: Getting session cookies...');
        const sessionResponse = await axiosInstance.get('https://www.zhihu.com/signin?next=%2F');
        
        // Extract cookies from the session response for the next request
        const cookies = sessionResponse.headers['set-cookie'];
        let cookieString = '';
        let xsrfToken = '';
        
        if (cookies) {
            cookieString = cookies.map(cookie => cookie.split(';')[0]).join('; ');
            // Try to extract XSRF token from cookies
            const xsrfCookie = cookies.find(cookie => cookie.includes('_xsrf='));
            if (xsrfCookie) {
                const match = xsrfCookie.match(/_xsrf=([^;]+)/);
                if (match) {
                    xsrfToken = match[1];
                    console.log('Found XSRF token:', xsrfToken);
                }
            }
        }
        
        // Now try the QR code API without the problematic headers
        console.log('Step 2: Calling QR code API...');
        const response = await axiosInstance.post('https://www.zhihu.com/api/v3/account/api/login/qrcode', null, {
            headers: {
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'x-requested-with': 'fetch',
                'x-xsrftoken': xsrfToken,
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'referer': 'https://www.zhihu.com/signin?next=%2F',
                'cookie': cookieString
            }
        });
        
        console.log('Status Code:', response.status);
        console.log('Response Headers:', JSON.stringify(response.headers, null, 2));
        console.log('Response Body:', JSON.stringify(response.data, null, 2));
        
        if (response.data && response.data.qrcode) {
            console.log('QR Code found in response!');
            console.log('QR Code length:', response.data.qrcode.length);
        }
        
        if (response.data && response.data.token) {
            console.log('Token found:', response.data.token);
        }
        
    } catch (error) {
        console.error('Error testing QR code API:', error.message);
        if (error.response) {
            console.error('Status Code:', error.response.status);
            console.error('Response Body:', JSON.stringify(error.response.data, null, 2));
        }
    }
}

testZhihuQRCodeAPI();
