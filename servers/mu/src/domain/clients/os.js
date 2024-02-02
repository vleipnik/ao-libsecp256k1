import { spawn } from 'child_process';

let procs = {};

function startMonitoredProcessWith({ logger }) {
    return async ({ id }) => {
        console.log('OS run ID:', id);
        const child = spawn('node', ['cranker/src/index.js', id], {
            stdio: 'ignore', // don't want the child's output to be attached to the parent
        });
        if (child && child.pid) {
            console.log(`Command executed with PID: ${child.pid}`);
            procs[id] = child;
            return child.pid;
        } else {
            console.log('Failed to execute command');
            throw new Error('Failed to execute command');
        }
    }
}

function killMonitoredProcessWith({ logger }) {
    return async ({ id }) => {
        const proc = procs[id];
        if (proc) {
            proc.kill()
            console.log(`Process with PID: ${proc.pid} has been killed.`);
            delete procs[id]; 
        } else {
            console.log(`No process found for ID: ${id}`);
            throw new Error(`No process found for ID: ${id}`);
        }
    }
}

export default {
    startMonitoredProcessWith,
    killMonitoredProcessWith
};