axios.interceptors.request.use(config => {
    const accessToken = localStorage.getItem('access');
    const refreshToken = localStorage.getItem('refresh');

     if(accessToken) {
        config.headers['Authorization'] = 'Bearer ${accessToken}';
     }
     if(refreshToken) {
        config.headers['Refresh'] = refreshToken;
     }
     return config;
     },
     error => {
     return Promise.reject(error);
});