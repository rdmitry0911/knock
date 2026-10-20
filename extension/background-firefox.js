import {registerBackground} from './background-dispatch.js';
import {performIce} from './ice-operation.js';
registerBackground(message=>performIce(message.operation,message.code,undefined,message.key));
