"""
:codeauthor: Shane Boissevain <sboissevain@nsslabs.com>
:date: 2019-01-05
"""
class GenericException(Exception):
    """ Base Exception class used to build up all other errors. """
    def __init__(self, message, errors=[]):
        super(Exception, self).__init__(message)
        self.errors = errors


    def __str__(self):
        """ Print the associated message and a readable list of "carried" errors.
        """
        # Initialize local variables
        ret_str = ""
        # Build the associated-error-list
        if len(self.errors) > 0:
            ret_str += "\nAssociated Error List\n"
        # For each associated error, add it to the return variable
        for error in self.errors:
            ret_str += str(error.__class__) + ":\n"
            ret_str += "\t--> " + str(error) + '\n'
        # Return the string representation of this error
        if self.errors == []:
            ret_str = str(self.message)
        else:
            ret_str += "\n" + str(self.message)
        return ret_str
