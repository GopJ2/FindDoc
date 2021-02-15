import axios from "axios";
import {AsyncStorage} from 'react-native';

const isProduction = process.env.PRODUCTION;
const URI = !isProduction ? 'http://192.168.0.110:8000' : 'something else';

let Api = axios.create({
    baseURL: URI
});

Api.interceptors.request.use((config) => {
    AsyncStorage.getItem('token').then(res => {
        if (res !== null && res !== '') {
            config.headers.credentials = 'include';
            config.headers.Authorization = `${res}`;
            config.headers['Access-Control-Allow-Origin'] = '*';
            config.headers['Content-Type'] = 'application/json';
        }else {
            config.headers.credentials = '';
            config.headers.Authorization = '';
        }
    })

    return config;
}, (error) => {
    return Promise.reject(error);
});

export default Api;