import React, {useEffect, useState} from "react";
import { NavigationContainer } from "@react-navigation/native";
import { createStackNavigator } from "@react-navigation/stack";
import HomePageTabNavigator from "./HomePageTabNavigator";
import LoginPageNavigator from "./LoginPageNavigator";
import {AsyncStorage} from 'react-native';

const Stack = createStackNavigator();

export default function() {
    const [userId, setUserId] = useState(null);

    useEffect(() => {
        let isMounted = true;
        AsyncStorage.getItem('userId').then(res => {
                if (isMounted) setUserId(res)
        })
        return () => { isMounted = false };
    })

    if (userId !== null) {
        return (
            <NavigationContainer>
                <Stack.Navigator screenOptions={{headerShown: false}}>
                    <Stack.Screen name={"Root"} component={HomePageTabNavigator}/>
                </Stack.Navigator>
            </NavigationContainer>
        );
    }

    return (
        <NavigationContainer>
            <Stack.Navigator screenOptions={{headerShown: false}}>
                <Stack.Screen name={"Root"} component={LoginPageNavigator}/>
            </Stack.Navigator>
        </NavigationContainer>
    )
}