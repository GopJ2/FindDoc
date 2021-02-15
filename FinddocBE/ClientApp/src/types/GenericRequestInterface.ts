import {AxiosRequestConfig} from "axios";

export interface AxiosPromise<T> extends Promise<AxiosResponse<T>> {
}

export interface AxiosResponse<T> {
    data: T;
    status: number;
    statusText: string;
    headers: any;
    config: AxiosRequestConfig;
}