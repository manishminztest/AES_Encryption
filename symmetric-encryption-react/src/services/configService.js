import apiService from "./apiService"

const login = (params) => {
  return apiService.post('/api/Login/login', params)
}

export const configService = {
    login,
}
