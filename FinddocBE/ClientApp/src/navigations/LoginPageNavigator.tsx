import {stackScreenOptions} from "./NavigationHelper";
import NavigationNames from "./NavigationNames";
import React from "react";
import {createStackNavigator} from "@react-navigation/stack";
import {LoginScreen} from "../screens/login";
import {ToolbarBrandLogo} from "../components/toolbar-brand-logo";
import {HomeScreen} from "../screens/home";

const Stack = createStackNavigator();

const LoginPageNavigator = () => {
    return (
        <Stack.Navigator headerMode="screen" screenOptions={stackScreenOptions}>
            <Stack.Screen
                name={NavigationNames.LoginScreen}
                component={LoginScreen}
                options={{ headerTitle: () => <ToolbarBrandLogo /> }}
            />
            <Stack.Screen
                name={NavigationNames.HomeScreen}
                component={HomeScreen}
                options={{ headerTitle: () => <ToolbarBrandLogo /> }}
            />
        </Stack.Navigator>
    );
}
export default LoginPageNavigator;