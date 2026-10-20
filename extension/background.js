import {registerBackground} from './background-dispatch.js';
import {sendIce} from './chromium-ice.js';
registerBackground(sendIce);
