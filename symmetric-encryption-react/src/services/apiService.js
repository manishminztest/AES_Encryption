import axios from 'axios';
import Cookies from 'universal-cookie';
import { baseURL } from '../utils/routes/PrivateRoutes';
import Swal from 'sweetalert2';

const cookies = new Cookies();
const API_BASE_URL = baseURL;

const getToken = () => cookies.get('authToken'); 

const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
});

axiosInstance.interceptors.request.use(
  (config) => {
    const token = getToken();
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    config.headers['Content-Type'] = 'application/json';
    return config;
  },
  (error) => Promise.reject(error)
);

const apiService = {
  get: (endpoint) => {
    return new Promise((resolve, reject) => {
      axiosInstance.get(endpoint)
        .then(response => resolve(response.data))
        .catch(error => {
          handleApiError(error);
          reject(error);
        });
    });
  },

  post: (endpoint, data) => {
    return new Promise((resolve, reject) => {
      axiosInstance.post(endpoint, data)
        .then(response => resolve(response.data))
        .catch(error => {
          handleApiError(error);
          reject(error);
        });
    });
  },

  put: (endpoint, data) => {
    return new Promise((resolve, reject) => {
      axiosInstance.put(endpoint, data)
        .then(response => resolve(response.data))
        .catch(error => {
          handleApiError(error);
          reject(error);
        });
    });
  },

  delete: (endpoint) => {
    return new Promise((resolve, reject) => {
      axiosInstance.delete(endpoint)
        .then(response => resolve(response.data))
        .catch(error => {
          handleApiError(error);
          reject(error);
        });
    });
  },
};

const handleApiError = (error) => {
  if (error.response) {
    Swal.fire({
      icon:'error',
      title: 'Error',
      text: error.response.data.message ?? 'Opps! something went wrong.'
    })
  } else if (error.request) {
    console.error('Error request data:', error.request);
  } else {
    console.error('Error message:', error.message);
  }
};

export default apiService;
