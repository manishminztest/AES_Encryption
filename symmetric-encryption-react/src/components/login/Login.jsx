import React, { useState } from 'react';
import axios from 'axios';
import validator from 'validator';
import { decrypt, encrypt, key } from '../../utils/aesEncryption/AesEncryption';
import { Box, Button, Grid, TextField, Typography } from '@mui/material';
import { baseURL, loginURL } from '../../utils/routes/PrivateRoutes';
import { configService } from '../../services/configService';

const Login = () => {
    const initialFormData = {
        email: "",
        password: ""
    }
    const [formData, setFormData] = useState(initialFormData);
    const [validationErrors, setValidationErrors] = useState({});
    const [responseText, setResponseText] = useState('');
    const [message, setMessage] = useState('');

    const handleChange = (e) => {
        try {
            const { name, value } = e.target;

            setFormData((prev) => ({
                ...prev,
                [name]: value
            }));

            if (validationErrors[name]) {
                setValidationErrors((prev) => ({
                    ...prev,
                    [name]: ""
                }));
            }
        }
        catch (e) {
            console.log(e);
        }
    }

    const validateForm = async () => {
        try {
            const errors = {};
            if (validator.isEmpty(formData.email)) {
                errors.email = "Required";
            }
            else if (!validator.isEmail(formData.email)) {
                errors.email = "Invalid email";
            }
            if (validator.isEmpty(formData.password)) {
                errors.password = "Required";
            }
            else if (!validator.isStrongPassword(formData.password, {
                minLength: 8, minLowercase: 1,
                minUppercase: 1, minNumbers: 1, minSymbols: 1
            })) {
                errors.password = "8 characters. 1 upper, lower, number and special symbol.";
            }
            setValidationErrors(errors);

            return Object.values(errors).every(error => error === "");
        }
        catch (e) {
            console.log(e);
        }
    }

    // Function to handle form submission and API request
    const handleSubmit = async (event) => {
        event.preventDefault();
        try {
            const isValid = await validateForm();
            if (isValid === false) {
                return false;
            }

            var plainText = JSON.stringify(formData);

            // Encrypt the plain text before sending
            const encryptedText = encrypt(plainText, key);

            // const url = baseURL + loginURL;
            // // Send the encrypted data to the API
            // const response = await axios.post(url, {
            //     data: encryptedText // Send the encrypted data
            // });

            const response = await configService.login({
                data: encryptedText // Send the encrypted data
            });

            // Decrypt the response data
            const decryptedResponse = decrypt(response.encryptedResponse, key);
            const result = response.message;
            setResponseText(decryptedResponse);
            setMessage(result);
        }
        catch (err) {
            console.error(err);
            setMessage(err.response.data.message);
            setResponseText('');
        }
    };

    // Function to reset
    const handleReset = () => {
        try {
            setFormData(initialFormData);
            setValidationErrors({});
            setResponseText('');
            setMessage('');
        }
        catch (e) {
            console.log(e);
        }
    }


    return (
        <Box mx={{ xs: 5, md: 30 }} my={{ xs: 10, md: 20 }} p={{ xs: 2, md: 5 }} border={'1px solid black'} borderRadius={10} bgcolor={'wheat'}>
            <h2>AES Encryption and Decryption with API</h2>
            <form onSubmit={handleSubmit} onReset={handleReset}>
                <Grid container alignItems={'center'} spacing={1}>
                    <Grid item xs={12} md={6}>
                        <Box display={'flex'} flexDirection={'column'} justifyContent={'center'}>
                            {
                                validationErrors.email ?
                                    <Typography variant='body1' color='error'>
                                        {validationErrors.email}
                                    </Typography>
                                    :
                                    <Typography variant='body1' color='success' fontSize={'bold'}>
                                        Email
                                    </Typography>
                            }
                            <TextField
                                type='text'
                                variant='outlined'
                                label='Email'
                                name='email'
                                onChange={handleChange}
                                value={formData.email}
                                errors={!!validationErrors.email}
                                sx={{ background: 'white' }}
                            />
                        </Box>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Box display={'flex'} flexDirection={'column'} justifyContent={'center'}>
                            {
                                validationErrors.password ?
                                    <Typography variant='body1' color='error'>
                                        {validationErrors.password}
                                    </Typography>
                                    :
                                    <Typography variant='body1' color='success' fontSize={'bold'}>
                                        Password
                                    </Typography>
                            }
                            <TextField
                                type='password'
                                variant='outlined'
                                label='Password'
                                name='password'
                                onChange={handleChange}
                                value={formData.password}
                                errors={!!validationErrors.password}
                                sx={{ background: 'white' }}
                            />
                        </Box>
                    </Grid>
                    <Grid container item justifyContent={'center'}>
                        <Button type='submit' variant='contained' color='primary' sx={{ maxWidth: 100, px: 5, py: 2 }}>
                            Login
                        </Button>
                        <Button type='reset' variant='contained' color='warning' sx={{ maxWidth: 100, px: 5, py: 2 }}>
                            Reset
                        </Button>
                    </Grid>
                </Grid>
            </form>
            {message && <p style={{ color: 'red' }}>{message}</p>}
            {
                responseText && (
                    <div>
                        <h3>Decrypted Response:</h3>
                        <p>{responseText}</p>
                    </div>
                )
            }
        </Box >
    );
};

export default Login;
