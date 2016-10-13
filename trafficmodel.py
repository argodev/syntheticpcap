#!/bin/env python

import logging
#import matplotlib.pyplot as plt
from scipy import interpolate
#import numpy as np

'''
Input:
    Hour : [0,24) (0 = midnight), can be a float (e.g. 1230 is 12.5)
    Weekend (false):  Set to true for saturday, sunday
Output:
    Float:  A scalar between [0,1] which can be used to scale down a duration constant, high values mean longer duration, low values mean lower duration
'''
def get_duration_scalar(hour,weekend=False):

    if (hour < 0 or hour >= 24):
        raise ValueError("hour must be [0,24), value given was "+str(hour))
    
    hour = (hour + 1) % 24
    #if (hour > 23):
    #    hour -= 23
    
        
    x = range(0,25)

# Crude hand-jammed points to characterize daily activity at hourly intervals
    if (weekend):
        y = [0,  #11PM
             .4, #12AM
             0,  #01AM
             0,  #02AM
             0,  #03AM
             0,  #04AM
             0,  #05AM
             0,  #06AM
             .1, #07AM
             .2, #08AM
             .5, #09AM
             .45,#10AM
             .45,#11AM
             .5, #12AM
             .45,#01PM
             .45,#02PM
             .45,#03PM
             .45, #04PM
             .5, #05PM
             .2, #06PM
             0,  #07PM
             0,  #08PM
             0,  #09PM
             0,  #10PM
             0,  #11PM since this isn't a circular array
             ]
    else:
        y = [0,  #11PM
             .4, #12AM
             0,  #01AM
             0,  #02AM
             0,  #03AM
             0,  #04AM
             0,  #05AM
             .1, #06AM
             .2, #07AM
             .4, #08AM
             .95,#09AM
             .9, #10AM
             .9, #11AM
             .95,#12AM
             .9, #01PM
             .9, #02PM
             .9, #03PM
             .9,#04PM
             .95, #05PM
             .4, #06PM
             .1, #07PM
             0,  #08PM
             0,  #09PM
             0,  #10PM
             0,  #11PM since this isn't a circular array
             ]
    
    
    f = interpolate.interp1d(x, y, kind='cubic')
    
    # We are using cubic splines to make the curve smooth, we need to prevent values out of range
    result = 1 - f(hour)
    if (result < 0):
        result = 0
    elif (result > 1):
        result = 1
    
    
    '''
    x1000  = np.arange(0, 24, 0.1)
    plt.figure()
    plt.plot(x, y, 'x', x1000, f(x1000),'b')
    plt.legend(['Points', ' Spline'])
    plt.show()
    '''
        
    return result


def main():
    logging.basicConfig(format='[%(asctime)s] %(message)s', level=logging.INFO)

    # show some times throughout a day
    logging.info("At 0100 in the morning: {0}".format(
            get_duration_scalar(1, False)))

    logging.info("At 0900 in the morning: {0}".format(
            get_duration_scalar(9, False)))

    logging.info("At 1230 in the afternoon: {0}".format(
            get_duration_scalar(12.5, False)))

    logging.info("At 1520 in the afternoon: {0}".format(
            get_duration_scalar(15.333, False)))

    logging.info("At 1845 in the evening: {0}".format(
            get_duration_scalar(18.75, False)))

    logging.info("At 2110 in the evening: {0}".format(
            get_duration_scalar(21.165, False)))


if __name__ == '__main__':
    main()
