// SPDX-License-Identifier: BUSL-1.1
import type {ReactNode} from 'react';
import type {Client,Identity,RequestSpec} from './api';
export type Common={client:Client;identity:Identity;revision:number;open:(title:string,content:ReactNode)=>void;done:(value:unknown,replayed:boolean)=>void;run:(title:string,description:string,spec:RequestSpec)=>void};
