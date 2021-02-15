import React, {useState} from "react";
import {StyleSheet, Text, TextInput, View, TouchableOpacity, AsyncStorage} from "react-native";
import {Theme} from "../../theme";
import Api from "../../services/ApiService";
import {AuthenticationModel} from "../../models/ServerData/AuthenticationModel";
import {useNavigation} from "@react-navigation/native";
import NavigationNames from "../../navigations/NavigationNames";

type TProps = {};

export const LoginScreen: React.FC<TProps> = props => {
    const navigation = useNavigation();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');

    const login = (): void => {
        const result = Api.post<AuthenticationModel>(`/api/login`, {
            email,
            password,
        })
            .then(res => {
                try {
                    AsyncStorage.setItem('token', res.data.token).then(res => navigation.navigate(NavigationNames.HomeScreen))
                }catch(e) {
                    console.error(e)
                }
            })
            .catch(e => console.error(e))
    }

    return (
        <View style={styles.container}>
            <View style={styles.titleContainer}>
                <Text style={styles.screenText}>
                    SIGN IN
                </Text>
            </View>
            <View style={styles.inputView} >
                <TextInput
                    style={styles.inputText}
                    placeholder="Email..."
                    placeholderTextColor="#003f5c"
                    onChangeText={text => setEmail(text)}/>
            </View>
            <View style={styles.inputView}>
                <TextInput
                    style={styles.inputText}
                    placeholder="Password..."
                    placeholderTextColor="#003f5c"
                    onChangeText={password => setPassword(password)}/>
            </View>
            <TouchableOpacity>
                <Text style={styles.forgot}>Forgot Password?</Text>
            </TouchableOpacity>
            <TouchableOpacity
                style={styles.loginBtn}
                onPress={login}
            >
                <Text style={styles.loginText}>LOGIN</Text>
            </TouchableOpacity>
            <TouchableOpacity>
                <Text style={styles.loginText}>Signup</Text>
            </TouchableOpacity>
        </View>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
    },
    inputView: {
        width:"80%",
        backgroundColor:"#465881",
        borderRadius:25,
        height:50,
        marginBottom:20,
        justifyContent:"center",
        padding:20
    },
    titleContainer: {
        marginBottom: 20,
        color: Theme.colors.black,
    },
    screenText: {
        fontSize: 24,

    },
    inputText: {
        height:50,
        color:"white"
    },
    forgot:{
        color:"white",
        fontSize:11
    },
    loginBtn:{
        width:"80%",
        backgroundColor:Theme.colors.primaryColor,
        borderRadius:25,
        height:50,
        alignItems:"center",
        justifyContent:"center",
        marginTop:40,
        marginBottom:10
    },
    loginText:{
        color:"white"
    },
});
